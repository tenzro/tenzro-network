//! The signed update metadata `tenzro update` trusts, and the checks on it.
//!
//! A TUF-style pair of signed documents, both in the envelope below:
//!
//! - **timestamp** (short-lived): which `targets` document is current, and
//!   until when this statement may be believed. Signed by an online key, so a
//!   stolen or lagging mirror cannot keep serving a stale `targets` for long
//!   (freeze attack).
//! - **targets** (long-lived): the release, its class, and every file with its
//!   length and SHA-256. Signed by the release key. Its `version` is a number
//!   that only ever goes up (rollback attack).
//!
//! The format is documented in `docs/UPDATE-MANIFEST.md`.
//!
//! Nothing here touches the disk or the network: callers hand in bytes, and
//! the verdict is a value. That is what makes it testable and keeps every
//! check ahead of the first write.

use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_device_key::signer::verify_p256;

pub const SPEC: &str = "tenzro-update/1";
const TIMESTAMP_DOMAIN: &[u8] = b"tenzro-update/1\ntimestamp\n";
const TARGETS_DOMAIN: &[u8] = b"tenzro-update/1\ntargets\n";
const LIBRARIES_DOMAIN: &[u8] = b"tenzro-update/1\nlibraries\n";

/// Largest `timestamp.json` / `targets.json` read from a channel.
pub const MAX_TIMESTAMP_BYTES: usize = 64 * 1024;
pub const MAX_TARGETS_BYTES: usize = 1024 * 1024;
pub const MAX_LIBRARIES_BYTES: usize = 1024 * 1024;
/// Most library files and links a libraries document lists.
pub const MAX_LIBRARY_ENTRIES: usize = 256;
/// Largest single file a manifest may list.
pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// A timestamp may be issued at most this far ahead of the local clock.
pub const MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;
/// Longest a timestamp may claim to be valid for.
pub const MAX_TIMESTAMP_LIFETIME_MS: u64 = 7 * 24 * 3600 * 1000;
/// The binaries a release may name. Nothing else is ever written.
pub const ALLOWED_NAMES: [&str; 2] = ["tenzro", "tenzro-node"];

/// The release key the installer verifies `SHA256SUMS` with (`scripts/install/install.sh`).
const RELEASE_KEY_SPKI_PEM: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3/NYEWx6w1OdV23xU656MhkpzxNM
PAP5jhmCYs7mWBx/W6lVL7cgwsTRlzcNq8iMIyU2lPMsmGNC7nZkxpaTZA==
-----END PUBLIC KEY-----";

/// Why metadata was refused. Each one names the attack or the fault.
#[derive(Debug, thiserror::Error)]
pub enum Reject {
    #[error("{0} is not a well-formed update document: {1}")]
    Malformed(&'static str, String),
    #[error("the {0} is not signed by a key this machine trusts")]
    BadSignature(&'static str),
    #[error("no key is trusted for the {0} role; add one to the trusted keys file")]
    NoKeys(&'static str),
    #[error(
        "the timestamp expired at {expired_ms} (now {now_ms}): the channel is serving stale metadata"
    )]
    Expired { expired_ms: u64, now_ms: u64 },
    #[error("the timestamp was issued in the future (clock skew over {} s)", MAX_CLOCK_SKEW_MS / 1000)]
    IssuedInFuture,
    #[error(
        "timestamp number {got} is lower than {seen}, which this machine already saw: refusing a replayed timestamp"
    )]
    TimestampRollback { got: u64, seen: u64 },
    #[error("the targets document does not match the signed timestamp ({0})")]
    TargetsMismatch(&'static str),
    #[error(
        "manifest number {got} is lower than {installed}, which is installed: refusing a rollback"
    )]
    ManifestRollback { got: u64, installed: u64 },
    #[error("release {release} is older than the installed {installed}: refusing a downgrade")]
    ReleaseRollback { release: String, installed: String },
    #[error("the libraries document is not the one of the verified targets document ({0})")]
    LibrariesMismatch(&'static str),
}

fn malformed(what: &'static str, why: impl fmt::Display) -> Reject {
    Reject::Malformed(what, why.to_string())
}

/// `major.minor.patch`, digits only. Pre-release tags are not releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(pub u64, pub u64, pub u64);

impl FromStr for Version {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let mut it = s.split('.');
        let mut n = || -> Result<u64, String> {
            let p = it
                .next()
                .ok_or_else(|| format!("{s:?} is not major.minor.patch"))?;
            if p.is_empty() || p.len() > 9 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(format!("{s:?} is not major.minor.patch"));
            }
            p.parse()
                .map_err(|_| format!("{s:?} is not major.minor.patch"))
        };
        let v = Version(n()?, n()?, n()?);
        if it.next().is_some() {
            return Err(format!("{s:?} is not major.minor.patch"));
        }
        Ok(v)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

impl Version {
    /// How many releases `self` is behind `latest`. Within one `major.minor`
    /// that is the patch difference. Across a minor or major line the release
    /// list is not in the manifest, so the answer is 2: more than one.
    pub fn releases_behind(&self, latest: &Version) -> u64 {
        if latest <= self {
            0
        } else if (self.0, self.1) == (latest.0, latest.1) {
            latest.2 - self.2
        } else {
            2
        }
    }
}

/// The signed envelope both documents travel in.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    /// Base64 of the exact bytes that were signed.
    pub payload: String,
    pub signatures: Vec<Signature>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    /// Hex SHA-256 of the signer's uncompressed SEC1 public key.
    pub keyid: String,
    /// ECDSA P-256 over SHA-256(domain || payload): hex raw `r || s` (64 bytes) or hex DER.
    pub sig: String,
}

pub fn key_id(sec1: &[u8]) -> String {
    hex::encode(Sha256::digest(sec1))
}

/// The keys this machine trusts, by role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRoot {
    pub targets: Vec<Vec<u8>>,
    pub timestamp: Vec<Vec<u8>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustRootFile {
    targets: Vec<String>,
    timestamp: Vec<String>,
}

impl TrustRoot {
    /// The release key the installer already trusts for `targets`. No key is
    /// provisioned for `timestamp` yet, so against this root nothing verifies
    /// until the release holder adds one (see `docs/UPDATE-MANIFEST.md`).
    pub fn embedded() -> Self {
        use p256::pkcs8::DecodePublicKey;
        let key = p256::PublicKey::from_public_key_pem(RELEASE_KEY_SPKI_PEM)
            .expect("the embedded release key parses");
        Self {
            targets: vec![key.to_sec1_bytes().to_vec()],
            timestamp: Vec::new(),
        }
    }

    /// `{"targets": [<hex SEC1 key>...], "timestamp": [<hex SEC1 key>...]}`.
    /// A file replaces the embedded root whole.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Reject> {
        let f: TrustRootFile =
            serde_json::from_slice(bytes).map_err(|e| malformed("trusted keys file", e))?;
        let keys = |v: Vec<String>| -> Result<Vec<Vec<u8>>, Reject> {
            v.iter()
                .map(|h| {
                    let k = hex::decode(h).map_err(|e| malformed("trusted keys file", e))?;
                    p256::PublicKey::from_sec1_bytes(&k)
                        .map_err(|_| malformed("trusted keys file", "not a P-256 public key"))?;
                    Ok(k)
                })
                .collect()
        };
        Ok(Self {
            targets: keys(f.targets)?,
            timestamp: keys(f.timestamp)?,
        })
    }
}

fn b64(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| e.to_string())
}

fn sig_bytes(hex_sig: &str) -> Option<Vec<u8>> {
    let raw = hex::decode(hex_sig).ok()?;
    if raw.len() == 64 {
        return Some(raw);
    }
    p256::ecdsa::Signature::from_der(&raw)
        .ok()
        .map(|s| s.to_bytes().to_vec())
}

/// Opens an envelope, checks one trusted key signed it, and returns the payload bytes.
fn open(
    what: &'static str,
    role: &'static str,
    domain: &[u8],
    keys: &[Vec<u8>],
    bytes: &[u8],
) -> Result<Vec<u8>, Reject> {
    if keys.is_empty() {
        return Err(Reject::NoKeys(role));
    }
    let env: Envelope = serde_json::from_slice(bytes).map_err(|e| malformed(what, e))?;
    let payload = b64(&env.payload).map_err(|e| malformed(what, e))?;
    let mut message = domain.to_vec();
    message.extend_from_slice(&payload);
    let ok = env.signatures.iter().any(|s| {
        keys.iter().any(|k| {
            key_id(k) == s.keyid
                && sig_bytes(&s.sig).is_some_and(|sig| verify_p256(k, &message, &sig))
        })
    });
    if !ok {
        return Err(Reject::BadSignature(role));
    }
    Ok(payload)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timestamp {
    #[serde(rename = "_type")]
    pub kind: String,
    pub spec: String,
    /// Increases with every timestamp the channel signs.
    pub version: u64,
    pub issued_ms: u64,
    pub expires_ms: u64,
    /// The `version` of the targets document this timestamp vouches for.
    pub targets_version: u64,
    pub targets_length: u64,
    /// Hex SHA-256 of the targets envelope file, exactly as served.
    pub targets_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Class {
    /// Node-local fixes, performance, CLI/UI, non-consensus security.
    C0,
    /// New consensus or state rules, shipped dormant.
    C1,
    /// Cannot be dormant: halt-at-height.
    C2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    /// `<arch>-<os>`, e.g. `x86_64-linux`.
    pub platform: String,
    /// `tenzro` or `tenzro-node`: the file it replaces in the install directory.
    pub name: String,
    /// Path under the channel's base URL or directory.
    pub path: String,
    pub length: u64,
    /// Hex SHA-256.
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Targets {
    #[serde(rename = "_type")]
    pub kind: String,
    pub spec: String,
    /// Monotonic manifest number.
    pub version: u64,
    /// Release version, `major.minor.patch`.
    pub release: String,
    pub class: Class,
    /// One line.
    pub description: String,
    pub files: Vec<FileEntry>,
}

fn lower_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A path under the channel: relative, `/`-separated, no climbing.
fn platform_ok(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 64
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn safe_path(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 256
        && !p.starts_with('/')
        && !p.contains(['\\', '\0'])
        && p.split('/').all(|c| !c.is_empty() && c != "." && c != "..")
}

impl Targets {
    pub fn release_version(&self) -> Version {
        self.release
            .parse()
            .expect("checked when the targets were verified")
    }

    fn check_shape(&self) -> Result<(), Reject> {
        let bad = |why: &str| Err(malformed("targets", why));
        if self.kind != "targets" || self.spec != SPEC {
            return bad("wrong type or spec");
        }
        if self.version == 0 {
            return bad("version 0");
        }
        if let Err(e) = self.release.parse::<Version>() {
            return bad(&e);
        }
        if self.description.is_empty()
            || self.description.len() > 200
            || self.description.contains(['\n', '\r'])
        {
            return bad("description is not one short line");
        }
        if self.files.is_empty() || self.files.len() > 64 {
            return bad("file list empty or too long");
        }
        let mut seen = std::collections::HashSet::new();
        for f in &self.files {
            if !ALLOWED_NAMES.contains(&f.name.as_str()) {
                return bad("a file names something other than tenzro or tenzro-node");
            }
            if !platform_ok(&f.platform) {
                return bad("bad platform");
            }
            if !safe_path(&f.path) {
                return bad("a file path is not a plain relative path");
            }
            if f.length == 0 || f.length > MAX_FILE_BYTES || !lower_hex64(&f.sha256) {
                return bad("a file has no length or no valid SHA-256");
            }
            if !seen.insert((f.platform.clone(), f.name.clone())) {
                return bad("a platform lists the same file twice");
            }
        }
        Ok(())
    }

    /// The files for `platform`.
    pub fn files_for<'a>(&'a self, platform: &'a str) -> impl Iterator<Item = &'a FileEntry> {
        self.files.iter().filter(move |f| f.platform == platform)
    }
}

/// The files a release keeps beside its two binaries, per platform: the
/// libraries under `lib/`, the ones Windows loads from `bin/`, and the web
/// console `tenzro control --web` serves, under `share/console/` with its
/// scripts in `share/console/src/`. Signed by the
/// targets key under its own domain and published beside `targets.json`, which
/// stays binaries only; it holds for exactly the release and manifest number
/// of the targets document it is checked against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Libraries {
    #[serde(rename = "_type")]
    pub kind: String,
    pub spec: String,
    /// The `version` of the targets document it belongs to.
    pub version: u64,
    /// The `release` of the targets document it belongs to.
    pub release: String,
    /// Hex SHA-256 of the payload of the targets document it belongs to.
    pub targets_sha256: String,
    /// `name` is `<folder>/<file>`, the folder one of [`LIBRARY_FOLDERS`].
    pub files: Vec<FileEntry>,
    pub links: Vec<LibraryLink>,
}

/// A symbolic link among a platform's library files, as the archive has it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibraryLink {
    pub platform: String,
    /// `lib/<file>`.
    pub name: String,
    /// A file of the same platform and folder, `lib/<file>`.
    pub target: String,
}

/// The folders of a release directory whose files the libraries document
/// carries; each is taken whole from the new release by an update.
pub const LIBRARY_FOLDERS: [&str; 4] = ["lib", "bin", "share/console", "share/console/src"];

/// `<folder>/<file>`: one plain file name directly in one of
/// [`LIBRARY_FOLDERS`], never one of the two binaries in any case (Windows
/// and macOS file systems ignore case, so `bin/Tenzro-Node.exe` is the node).
fn library_name_ok(name: &str) -> bool {
    let Some((dir, file)) = name.rsplit_once('/') else {
        return false;
    };
    LIBRARY_FOLDERS.contains(&dir)
        && !file.is_empty()
        && file.len() <= 128
        && !file.starts_with('.')
        && file
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
        && !(dir == "bin"
            && ALLOWED_NAMES.iter().any(|n| {
                file.eq_ignore_ascii_case(n) || file.eq_ignore_ascii_case(&format!("{n}.exe"))
            }))
}

impl Libraries {
    fn check_shape(&self) -> Result<(), Reject> {
        let bad = |why: &str| Err(malformed("libraries", why));
        if self.kind != "libraries" || self.spec != SPEC {
            return bad("wrong type or spec");
        }
        if self.release.parse::<Version>().is_err() || self.version == 0 {
            return bad("no release or manifest number");
        }
        if !lower_hex64(&self.targets_sha256) {
            return bad("no targets digest");
        }
        if self.files.len() + self.links.len() > MAX_LIBRARY_ENTRIES {
            return bad("too many entries");
        }
        // Names are told apart without regard to case, as the file systems that ignore it do.
        let mut seen = std::collections::HashSet::new();
        for f in &self.files {
            if !platform_ok(&f.platform) {
                return bad("bad platform");
            }
            if !library_name_ok(&f.name) {
                return bad("a library is not one file in lib/ or bin/");
            }
            if !safe_path(&f.path) {
                return bad("a file path is not a plain relative path");
            }
            if f.length == 0 || f.length > MAX_FILE_BYTES || !lower_hex64(&f.sha256) {
                return bad("a file has no length or no valid SHA-256");
            }
            if !seen.insert((f.platform.as_str(), f.name.to_ascii_lowercase())) {
                return bad("a platform lists the same library twice");
            }
        }
        for l in &self.links {
            if !platform_ok(&l.platform) || !l.name.starts_with("lib/") || !library_name_ok(&l.name)
            {
                return bad("a link is not one name in lib/");
            }
            if !self.files.iter().any(|f| {
                f.platform == l.platform && f.name == l.target && f.name.starts_with("lib/")
            }) {
                return bad("a link points at no library file of its platform");
            }
            if !seen.insert((l.platform.as_str(), l.name.to_ascii_lowercase())) {
                return bad("a platform lists the same library twice");
            }
        }
        Ok(())
    }

    /// The library files for `platform`.
    pub fn files_for<'a>(&'a self, platform: &'a str) -> impl Iterator<Item = &'a FileEntry> {
        self.files.iter().filter(move |f| f.platform == platform)
    }

    /// The links for `platform`.
    pub fn links_for<'a>(&'a self, platform: &'a str) -> impl Iterator<Item = &'a LibraryLink> {
        self.links.iter().filter(move |l| l.platform == platform)
    }
}

/// Checks a libraries document: signed by a trusted targets key, well formed,
/// and for exactly the targets document of `verified` (its payload digest,
/// release and manifest number), which was checked against the timestamp, so
/// the libraries are as fresh as it is.
pub fn verify_libraries(
    bytes: &[u8],
    root: &TrustRoot,
    verified: &Verified,
) -> Result<Libraries, Reject> {
    let targets = &verified.targets;
    let lib: Libraries = serde_json::from_slice(&open(
        "libraries",
        "libraries",
        LIBRARIES_DOMAIN,
        &root.targets,
        bytes,
    )?)
    .map_err(|e| malformed("libraries", e))?;
    lib.check_shape()?;
    if lib.targets_sha256 != verified.targets_payload_sha256 {
        return Err(Reject::LibrariesMismatch("targets digest"));
    }
    if lib.release != targets.release {
        return Err(Reject::LibrariesMismatch("release"));
    }
    if lib.version != targets.version {
        return Err(Reject::LibrariesMismatch("manifest number"));
    }
    Ok(lib)
}

/// What this machine already knows.
#[derive(Debug, Clone)]
pub struct Local {
    /// Highest manifest number installed here; `0` if `tenzro update` never installed one.
    pub installed_manifest_version: u64,
    /// Highest timestamp number ever seen.
    pub highest_timestamp_version: u64,
    /// The release in the install directory (`install::installed_release`).
    pub installed_release: Version,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub timestamp_version: u64,
    pub targets: Targets,
    /// Hex SHA-256 of the targets payload, the exact bytes the targets key signed.
    pub targets_payload_sha256: String,
}

impl Verified {
    /// Whether this is an update to something newer than what runs here: a
    /// manifest number above the installed one and a release above the installed one.
    pub fn is_newer(&self, local: &Local) -> bool {
        self.targets.version > local.installed_manifest_version
            && self.targets.release_version() > local.installed_release
    }
}

/// Verifies `timestamp.json` and `targets.json` as served, at `now_ms`.
///
/// Fails closed on: an untrusted or missing signature, an expired or
/// replayed timestamp, a targets document that is not the one the timestamp
/// vouches for, a manifest number below the installed one, and a release
/// below the installed one. A manifest number equal to the installed one
/// verifies; [`Verified::is_newer`] says it is not an update.
pub fn verify(
    timestamp: &[u8],
    targets: &[u8],
    root: &TrustRoot,
    local: &Local,
    now_ms: u64,
) -> Result<Verified, Reject> {
    let ts: Timestamp = serde_json::from_slice(&open(
        "timestamp",
        "timestamp",
        TIMESTAMP_DOMAIN,
        &root.timestamp,
        timestamp,
    )?)
    .map_err(|e| malformed("timestamp", e))?;
    if ts.kind != "timestamp" || ts.spec != SPEC || !lower_hex64(&ts.targets_sha256) {
        return Err(malformed("timestamp", "wrong type, spec or hash"));
    }
    if ts.expires_ms <= ts.issued_ms || ts.expires_ms - ts.issued_ms > MAX_TIMESTAMP_LIFETIME_MS {
        return Err(malformed("timestamp", "lifetime out of bounds"));
    }
    if ts.expires_ms <= now_ms {
        return Err(Reject::Expired {
            expired_ms: ts.expires_ms,
            now_ms,
        });
    }
    if ts.issued_ms > now_ms.saturating_add(MAX_CLOCK_SKEW_MS) {
        return Err(Reject::IssuedInFuture);
    }
    if ts.version < local.highest_timestamp_version {
        return Err(Reject::TimestampRollback {
            got: ts.version,
            seen: local.highest_timestamp_version,
        });
    }

    if targets.len() as u64 != ts.targets_length {
        return Err(Reject::TargetsMismatch("length"));
    }
    if hex::encode(Sha256::digest(targets)) != ts.targets_sha256 {
        return Err(Reject::TargetsMismatch("SHA-256"));
    }
    let payload = open("targets", "targets", TARGETS_DOMAIN, &root.targets, targets)?;
    let targets_payload_sha256 = hex::encode(Sha256::digest(&payload));
    let tg: Targets = serde_json::from_slice(&payload).map_err(|e| malformed("targets", e))?;
    tg.check_shape()?;
    if tg.version != ts.targets_version {
        return Err(Reject::TargetsMismatch("version"));
    }
    if tg.version < local.installed_manifest_version {
        return Err(Reject::ManifestRollback {
            got: tg.version,
            installed: local.installed_manifest_version,
        });
    }
    if tg.release_version() < local.installed_release {
        return Err(Reject::ReleaseRollback {
            release: tg.release.clone(),
            installed: local.installed_release.to_string(),
        });
    }
    Ok(Verified {
        timestamp_version: ts.version,
        targets: tg,
        targets_payload_sha256,
    })
}

#[cfg(test)]
pub(crate) mod fixture {
    //! Signs metadata the way a release tool would, for tests.
    use super::*;
    use p256::ecdsa::signature::hazmat::PrehashSigner;

    pub struct Key(p256::ecdsa::SigningKey);

    impl Key {
        pub fn new(seed: u8) -> Self {
            let mut scalar = [0u8; 32];
            scalar[0] = 0x21;
            scalar[31] = seed.max(1);
            Self(p256::ecdsa::SigningKey::from_slice(&scalar).unwrap())
        }
        pub fn sec1(&self) -> Vec<u8> {
            self.0
                .verifying_key()
                .to_sec1_point(false)
                .as_bytes()
                .to_vec()
        }
        fn envelope(&self, domain: &[u8], payload: &[u8]) -> Vec<u8> {
            let mut m = domain.to_vec();
            m.extend_from_slice(payload);
            let digest: [u8; 32] = Sha256::digest(&m).into();
            let sig: p256::ecdsa::Signature = self.0.sign_prehash(&digest).unwrap();
            serde_json::to_vec(&Envelope {
                payload: base64::engine::general_purpose::STANDARD.encode(payload),
                signatures: vec![Signature {
                    keyid: key_id(&self.sec1()),
                    sig: hex::encode(sig.to_bytes()),
                }],
            })
            .unwrap()
        }
        pub fn sign_targets(&self, t: &Targets) -> Vec<u8> {
            self.envelope(TARGETS_DOMAIN, &serde_json::to_vec(t).unwrap())
        }
        pub fn sign_timestamp(&self, t: &Timestamp) -> Vec<u8> {
            self.envelope(TIMESTAMP_DOMAIN, &serde_json::to_vec(t).unwrap())
        }
        pub fn sign_libraries(&self, l: &Libraries) -> Vec<u8> {
            self.envelope(LIBRARIES_DOMAIN, &serde_json::to_vec(l).unwrap())
        }
    }

    pub const NOW: u64 = 1_900_000_000_000;

    pub fn root(targets: &Key, timestamp: &Key) -> TrustRoot {
        TrustRoot {
            targets: vec![targets.sec1()],
            timestamp: vec![timestamp.sec1()],
        }
    }

    pub fn targets(version: u64, release: &str, files: Vec<FileEntry>) -> Targets {
        Targets {
            kind: "targets".into(),
            spec: SPEC.into(),
            version,
            release: release.into(),
            class: Class::C0,
            description: "Fixes a checkpoint submission stall".into(),
            files,
        }
    }

    pub fn file(name: &str, content: &[u8]) -> FileEntry {
        FileEntry {
            platform: "x86_64-linux".into(),
            name: name.into(),
            path: format!("files/{name}"),
            length: content.len() as u64,
            sha256: hex::encode(Sha256::digest(content)),
        }
    }

    /// A timestamp vouching for `targets_file` as served.
    pub fn timestamp_for(
        targets: &Targets,
        targets_file: &[u8],
        version: u64,
        issued_ms: u64,
        lifetime_ms: u64,
    ) -> Timestamp {
        Timestamp {
            kind: "timestamp".into(),
            spec: SPEC.into(),
            version,
            issued_ms,
            expires_ms: issued_ms + lifetime_ms,
            targets_version: targets.version,
            targets_length: targets_file.len() as u64,
            targets_sha256: hex::encode(Sha256::digest(targets_file)),
        }
    }

    pub fn local() -> Local {
        Local {
            installed_manifest_version: 3,
            highest_timestamp_version: 10,
            installed_release: "0.2.1".parse().unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::*;
    use super::*;

    const HOUR: u64 = 3_600_000;

    struct Served {
        timestamp: Vec<u8>,
        targets: Vec<u8>,
    }

    fn serve(
        tk: &Key,
        sk: &Key,
        t: &Targets,
        ts_version: u64,
        issued: u64,
        lifetime: u64,
    ) -> Served {
        let targets = tk.sign_targets(t);
        let ts = timestamp_for(t, &targets, ts_version, issued, lifetime);
        Served {
            timestamp: sk.sign_timestamp(&ts),
            targets,
        }
    }

    fn good_targets() -> Targets {
        targets(
            4,
            "0.2.2",
            vec![file("tenzro", b"new cli"), file("tenzro-node", b"new node")],
        )
    }

    fn library(platform: &str, name: &str, content: &[u8]) -> FileEntry {
        FileEntry {
            platform: platform.into(),
            name: name.into(),
            path: format!("0.2.2/{platform}/{name}"),
            ..file("tenzro", content)
        }
    }

    fn verified_targets() -> Verified {
        Verified {
            timestamp_version: 11,
            targets: good_targets(),
            targets_payload_sha256: hex::encode(Sha256::digest(
                serde_json::to_vec(&good_targets()).unwrap(),
            )),
        }
    }

    fn good_libraries() -> Libraries {
        Libraries {
            kind: "libraries".into(),
            spec: SPEC.into(),
            version: 4,
            release: "0.2.2".into(),
            targets_sha256: verified_targets().targets_payload_sha256,
            files: vec![
                library("x86_64-linux-cuda", "lib/libonnxruntime.so.1.22.0", b"ort"),
                library("x86_64-windows-cuda", "bin/onnxruntime.dll", b"ort dll"),
            ],
            links: vec![LibraryLink {
                platform: "x86_64-linux-cuda".into(),
                name: "lib/libonnxruntime.so.1".into(),
                target: "lib/libonnxruntime.so.1.22.0".into(),
            }],
        }
    }

    #[test]
    fn the_console_and_its_scripts_are_library_folders() {
        for name in [
            "share/console/index.html",
            "share/console/manifest.webmanifest",
            "share/console/src/app.js",
            "lib/libonnxruntime.so.1",
            "bin/onnxruntime.dll",
        ] {
            assert!(library_name_ok(name), "{name}");
        }
    }

    #[test]
    fn a_libraries_document_of_the_verified_targets_is_accepted() {
        let tk = Key::new(1);
        let root = root(&tk, &Key::new(2));
        let l = verify_libraries(
            &tk.sign_libraries(&good_libraries()),
            &root,
            &verified_targets(),
        )
        .unwrap();
        assert_eq!(l.files_for("x86_64-linux-cuda").count(), 1);
        assert_eq!(l.links_for("x86_64-linux-cuda").count(), 1);
        assert_eq!(l.files_for("x86_64-linux").count(), 0);
    }

    #[test]
    fn a_libraries_document_of_another_release_key_or_shape_is_refused() {
        let tk = Key::new(1);
        let root = root(&tk, &Key::new(2));
        let refused = |l: &Libraries, key: &Key| {
            verify_libraries(&key.sign_libraries(l), &root, &verified_targets()).unwrap_err()
        };
        let mut other = good_libraries();
        other.release = "0.2.9".into();
        assert!(matches!(
            refused(&other, &tk),
            Reject::LibrariesMismatch("release")
        ));
        let mut other = good_libraries();
        other.targets_sha256 = "0".repeat(64);
        assert!(matches!(
            refused(&other, &tk),
            Reject::LibrariesMismatch("targets digest")
        ));
        let mut other = good_libraries();
        other.version = 5;
        assert!(matches!(
            refused(&other, &tk),
            Reject::LibrariesMismatch("manifest number")
        ));
        // The timestamp key, or any key not trusted for targets, signs no libraries.
        assert!(matches!(
            refused(&good_libraries(), &Key::new(2)),
            Reject::BadSignature(_)
        ));
        // A targets envelope is not a libraries document: the domains differ.
        assert!(matches!(
            verify_libraries(
                &tk.sign_targets(&good_targets()),
                &root,
                &verified_targets()
            )
            .unwrap_err(),
            Reject::BadSignature(_)
        ));
        for name in [
            "lib/../x",
            "lib/.hidden",
            "etc/libx.so",
            "lib/a/b.so",
            "lib/",
            "share/network/13380.toml",
            "share/console/src/deep/x.js",
            "share/x.js",
            "share/console/.hidden",
            "bin/tenzro-node.exe",
            "bin/Tenzro-Node.exe",
            "bin/TENZRO.EXE",
            "bin/tenzro",
            "libx.so",
        ] {
            let mut bad = good_libraries();
            bad.files[0].name = name.into();
            bad.links.clear();
            assert!(
                matches!(refused(&bad, &tk), Reject::Malformed("libraries", _)),
                "{name}"
            );
        }
        let mut dangling = good_libraries();
        dangling.links[0].target = "lib/libmissing.so".into();
        assert!(matches!(
            refused(&dangling, &tk),
            Reject::Malformed("libraries", _)
        ));
        let mut cross = good_libraries();
        cross.links[0].platform = "x86_64-windows-cuda".into();
        assert!(matches!(
            refused(&cross, &tk),
            Reject::Malformed("libraries", _)
        ));
        let mut cased = good_libraries();
        cased.files.push(library(
            "x86_64-linux-cuda",
            "lib/LIBONNXRUNTIME.so.1.22.0",
            b"same file on a case-blind file system",
        ));
        assert!(matches!(
            refused(&cased, &tk),
            Reject::Malformed("libraries", _)
        ));
        let mut twice = good_libraries();
        twice.links[0].name = "lib/libonnxruntime.so.1.22.0".into();
        twice.links[0].target = "lib/libonnxruntime.so.1.22.0".into();
        assert!(matches!(
            refused(&twice, &tk),
            Reject::Malformed("libraries", _)
        ));
    }

    #[test]
    fn a_validly_signed_newer_manifest_is_accepted() {
        let (tk, sk) = (Key::new(1), Key::new(2));
        let s = serve(&tk, &sk, &good_targets(), 11, NOW - HOUR, 24 * HOUR);
        let v = verify(&s.timestamp, &s.targets, &root(&tk, &sk), &local(), NOW).unwrap();
        assert_eq!(v.targets.release, "0.2.2");
        assert_eq!(v.timestamp_version, 11);
        assert!(v.is_newer(&local()));
    }

    #[test]
    fn a_der_encoded_signature_is_accepted_too() {
        let (tk, sk) = (Key::new(1), Key::new(2));
        let s = serve(&tk, &sk, &good_targets(), 11, NOW - HOUR, 24 * HOUR);
        let mut env: Envelope = serde_json::from_slice(&s.targets).unwrap();
        let raw = hex::decode(&env.signatures[0].sig).unwrap();
        env.signatures[0].sig = hex::encode(
            p256::ecdsa::Signature::from_slice(&raw)
                .unwrap()
                .to_der()
                .as_bytes(),
        );
        let targets = serde_json::to_vec(&env).unwrap();
        // The timestamp vouches for the targets file byte for byte, so re-issue it.
        let ts = timestamp_for(&good_targets(), &targets, 11, NOW - HOUR, 24 * HOUR);
        verify(
            &sk.sign_timestamp(&ts),
            &targets,
            &root(&tk, &sk),
            &local(),
            NOW,
        )
        .unwrap();
    }

    #[test]
    fn a_tampered_file_list_is_rejected() {
        let (tk, sk) = (Key::new(1), Key::new(2));
        let s = serve(&tk, &sk, &good_targets(), 11, NOW - HOUR, 24 * HOUR);
        // An attacker swaps a hash inside the payload but keeps the signature.
        let mut env: Envelope = serde_json::from_slice(&s.targets).unwrap();
        let mut t: Targets = serde_json::from_slice(&b64(&env.payload).unwrap()).unwrap();
        t.files[0].sha256 = "0".repeat(64);
        env.payload =
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&t).unwrap());
        let tampered = serde_json::to_vec(&env).unwrap();
        // Even with a timestamp that vouches for the tampered bytes, the targets signature fails.
        let ts = timestamp_for(&t, &tampered, 11, NOW - HOUR, 24 * HOUR);
        let e = verify(
            &sk.sign_timestamp(&ts),
            &tampered,
            &root(&tk, &sk),
            &local(),
            NOW,
        )
        .unwrap_err();
        assert!(matches!(e, Reject::BadSignature("targets")), "{e}");
        // And against the genuine timestamp the swapped bytes are not the vouched-for file.
        let e = verify(&s.timestamp, &tampered, &root(&tk, &sk), &local(), NOW).unwrap_err();
        assert!(matches!(e, Reject::TargetsMismatch(_)), "{e}");
    }

    #[test]
    fn a_manifest_signed_by_an_untrusted_key_is_rejected() {
        let (tk, sk, evil) = (Key::new(1), Key::new(2), Key::new(9));
        let s = serve(&evil, &sk, &good_targets(), 11, NOW - HOUR, 24 * HOUR);
        let e = verify(&s.timestamp, &s.targets, &root(&tk, &sk), &local(), NOW).unwrap_err();
        assert!(matches!(e, Reject::BadSignature("targets")), "{e}");
        // The targets key cannot stand in for the timestamp key (role separation).
        let s = serve(&tk, &tk, &good_targets(), 11, NOW - HOUR, 24 * HOUR);
        let e = verify(&s.timestamp, &s.targets, &root(&tk, &sk), &local(), NOW).unwrap_err();
        assert!(matches!(e, Reject::BadSignature("timestamp")), "{e}");
    }

    #[test]
    fn a_manifest_number_below_the_installed_one_is_rejected_as_a_rollback() {
        let (tk, sk) = (Key::new(1), Key::new(2));
        let s = serve(
            &tk,
            &sk,
            &targets(2, "0.2.2", vec![file("tenzro", b"x")]),
            11,
            NOW - HOUR,
            24 * HOUR,
        );
        let e = verify(&s.timestamp, &s.targets, &root(&tk, &sk), &local(), NOW).unwrap_err();
        assert!(
            matches!(
                e,
                Reject::ManifestRollback {
                    got: 2,
                    installed: 3
                }
            ),
            "{e}"
        );
    }

    #[test]
    fn a_manifest_number_equal_to_the_installed_one_is_no_update() {
        let (tk, sk) = (Key::new(1), Key::new(2));
        let s = serve(
            &tk,
            &sk,
            &targets(3, "0.2.2", vec![file("tenzro", b"x")]),
            11,
            NOW - HOUR,
            24 * HOUR,
        );
        let v = verify(&s.timestamp, &s.targets, &root(&tk, &sk), &local(), NOW).unwrap();
        assert!(!v.is_newer(&local()));
    }

    #[test]
    fn a_release_older_than_the_installed_one_is_rejected_whatever_its_number() {
        let (tk, sk) = (Key::new(1), Key::new(2));
        let s = serve(
            &tk,
            &sk,
            &targets(9, "0.2.0", vec![file("tenzro", b"x")]),
            11,
            NOW - HOUR,
            24 * HOUR,
        );
        let e = verify(&s.timestamp, &s.targets, &root(&tk, &sk), &local(), NOW).unwrap_err();
        assert!(matches!(e, Reject::ReleaseRollback { .. }), "{e}");
    }

    #[test]
    fn an_expired_timestamp_is_rejected_as_a_freeze() {
        let (tk, sk) = (Key::new(1), Key::new(2));
        let s = serve(&tk, &sk, &good_targets(), 11, NOW - 48 * HOUR, 24 * HOUR);
        let e = verify(&s.timestamp, &s.targets, &root(&tk, &sk), &local(), NOW).unwrap_err();
        assert!(matches!(e, Reject::Expired { .. }), "{e}");
    }

    #[test]
    fn a_replayed_older_timestamp_is_rejected() {
        let (tk, sk) = (Key::new(1), Key::new(2));
        let s = serve(&tk, &sk, &good_targets(), 9, NOW - HOUR, 24 * HOUR);
        let e = verify(&s.timestamp, &s.targets, &root(&tk, &sk), &local(), NOW).unwrap_err();
        assert!(
            matches!(e, Reject::TimestampRollback { got: 9, seen: 10 }),
            "{e}"
        );
    }

    #[test]
    fn a_timestamp_from_the_future_is_rejected() {
        let (tk, sk) = (Key::new(1), Key::new(2));
        let s = serve(&tk, &sk, &good_targets(), 11, NOW + HOUR, 24 * HOUR);
        let e = verify(&s.timestamp, &s.targets, &root(&tk, &sk), &local(), NOW).unwrap_err();
        assert!(matches!(e, Reject::IssuedInFuture), "{e}");
    }

    #[test]
    fn a_targets_file_the_timestamp_does_not_vouch_for_is_rejected() {
        let (tk, sk) = (Key::new(1), Key::new(2));
        let s = serve(&tk, &sk, &good_targets(), 11, NOW - HOUR, 24 * HOUR);
        // A genuinely signed but different (older) targets document.
        let other = tk.sign_targets(&targets(3, "0.2.1", vec![file("tenzro", b"old")]));
        let e = verify(&s.timestamp, &other, &root(&tk, &sk), &local(), NOW).unwrap_err();
        assert!(matches!(e, Reject::TargetsMismatch(_)), "{e}");
    }

    #[test]
    fn a_root_with_no_timestamp_key_fails_closed() {
        let tk = Key::new(1);
        let s = serve(&tk, &tk, &good_targets(), 11, NOW - HOUR, 24 * HOUR);
        let e = verify(
            &s.timestamp,
            &s.targets,
            &TrustRoot::embedded(),
            &local(),
            NOW,
        )
        .unwrap_err();
        assert!(matches!(e, Reject::NoKeys("timestamp")), "{e}");
    }

    #[test]
    fn hostile_file_entries_are_rejected() {
        let (tk, sk) = (Key::new(1), Key::new(2));
        for mutate in [
            (|f: &mut FileEntry| f.path = "../../etc/passwd".into()) as fn(&mut FileEntry),
            |f| f.path = "/abs".into(),
            |f| f.name = "sh".into(),
            |f| f.sha256 = "ABC".into(),
            |f| f.length = 0,
        ] {
            let mut t = good_targets();
            mutate(&mut t.files[0]);
            let s = serve(&tk, &sk, &t, 11, NOW - HOUR, 24 * HOUR);
            let e = verify(&s.timestamp, &s.targets, &root(&tk, &sk), &local(), NOW).unwrap_err();
            assert!(matches!(e, Reject::Malformed("targets", _)), "{e}");
        }
    }

    #[test]
    fn the_embedded_key_is_the_installers_and_versions_compare_numerically() {
        let installer = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../scripts/install/install.sh"
        ))
        .unwrap();
        let body: String = RELEASE_KEY_SPKI_PEM
            .lines()
            .skip(1)
            .take(2)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            installer.contains(&body),
            "the embedded release key differs from install.sh"
        );
        assert_eq!(TrustRoot::embedded().targets.len(), 1);
        assert!("0.10.0".parse::<Version>().unwrap() > "0.9.9".parse().unwrap());
        assert!("0.2".parse::<Version>().is_err() && "0.2.1-rc1".parse::<Version>().is_err());
        let v: Version = "0.2.1".parse().unwrap();
        assert_eq!(v.releases_behind(&"0.2.1".parse().unwrap()), 0);
        assert_eq!(v.releases_behind(&"0.2.2".parse().unwrap()), 1);
        assert_eq!(v.releases_behind(&"0.2.4".parse().unwrap()), 3);
        assert_eq!(v.releases_behind(&"0.3.0".parse().unwrap()), 2);
    }

    #[test]
    fn a_trusted_keys_file_replaces_the_embedded_root() {
        let (tk, sk) = (Key::new(1), Key::new(2));
        let json = serde_json::json!({ "targets": [hex::encode(tk.sec1())], "timestamp": [hex::encode(sk.sec1())] });
        let r = TrustRoot::from_json(json.to_string().as_bytes()).unwrap();
        assert_eq!(r, root(&tk, &sk));
        assert!(TrustRoot::from_json(br#"{"targets":["00"],"timestamp":[]}"#).is_err());
    }
}
