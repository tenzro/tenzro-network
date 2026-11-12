//! The notice document, its signature and the checks a node applies to it.
//!
//! The envelope is the one `tenzro update` already uses for its manifests: the
//! exact signed bytes in base64 and one or more signatures, each naming its key
//! by the SHA-256 of the uncompressed SEC1 public key. The signed message is a
//! domain string followed by the payload, so a signature made for a notice is
//! worth nothing on a manifest and the reverse.

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use base64::Engine as _;
use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Format identifier of the notice payload.
pub const SPEC: &str = "tenzro-notice/1";
const DOMAIN: &[u8] = b"tenzro-update/1\nnotice\n";

/// Largest signed notice a node reads from a file, the network or a peer.
pub const MAX_ENVELOPE_BYTES: usize = 32 * 1024;
/// Longest release note, in characters.
pub const MAX_NOTES_CHARS: usize = 2000;
/// Longest a notice may stay valid after it was issued.
pub const MAX_LIFETIME_MS: u64 = 180 * 24 * 3600 * 1000;
/// A notice may be issued at most this far ahead of the local clock.
pub const MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;
/// Most platform archives one notice lists.
pub const MAX_PLATFORMS: usize = 16;
/// Largest archive a notice may list.
pub const MAX_ARCHIVE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// The release key the installers verify `SHA256SUMS` with (`scripts/install/install.sh`).
const RELEASE_KEY_SPKI_PEM: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3/NYEWx6w1OdV23xU656MhkpzxNM
PAP5jhmCYs7mWBx/W6lVL7cgwsTRlzcNq8iMIyU2lPMsmGNC7nZkxpaTZA==
-----END PUBLIC KEY-----";

/// A P-256 public key in PEM (SubjectPublicKeyInfo), as uncompressed SEC1.
pub fn public_key_from_pem(pem: &str) -> Result<Vec<u8>, NoticeError> {
    use p256::pkcs8::DecodePublicKey;
    p256::PublicKey::from_public_key_pem(pem)
        .map(|k| k.to_sec1_bytes().to_vec())
        .map_err(|e| malformed(format!("public key: {e}")))
}

/// The embedded release public key, uncompressed SEC1.
pub fn release_key_sec1() -> Vec<u8> {
    use p256::pkcs8::DecodePublicKey;
    p256::PublicKey::from_public_key_pem(RELEASE_KEY_SPKI_PEM)
        .expect("the embedded release key parses")
        .to_sec1_bytes()
        .to_vec()
}

/// The embedded release key's fingerprint: SHA-256 of its DER SubjectPublicKeyInfo, hex.
pub fn release_key_fingerprint() -> String {
    use p256::pkcs8::DecodePublicKey;
    let key = p256::PublicKey::from_public_key_pem(RELEASE_KEY_SPKI_PEM)
        .expect("the embedded release key parses");
    fingerprint(&key)
}

/// SHA-256 of a key's DER SubjectPublicKeyInfo, hex.
pub fn fingerprint(key: &p256::PublicKey) -> String {
    use p256::pkcs8::EncodePublicKey;
    let der = key.to_public_key_der().expect("a P-256 key encodes");
    hex::encode(Sha256::digest(der.as_bytes()))
}

/// The keys a node trusts for notices: the `targets` list of
/// `<data_dir>/update/trusted-keys.json` when that file exists (the same file
/// `tenzro update` reads), else the embedded release key.
pub fn trusted_keys(data_dir: &Path) -> Result<Vec<Vec<u8>>, NoticeError> {
    #[derive(Deserialize)]
    struct File {
        targets: Vec<String>,
    }
    let path = data_dir.join("update").join("trusted-keys.json");
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![release_key_sec1()]),
        Err(e) => {
            return Err(NoticeError::Malformed(format!(
                "read {}: {e}",
                path.display()
            )));
        }
    };
    let f: File = serde_json::from_slice(&bytes)
        .map_err(|e| NoticeError::Malformed(format!("{}: {e}", path.display())))?;
    f.targets
        .iter()
        .map(|h| {
            let k = hex::decode(h)
                .map_err(|e| NoticeError::Malformed(format!("{}: {e}", path.display())))?;
            p256::PublicKey::from_sec1_bytes(&k).map_err(|_| {
                NoticeError::Malformed(format!("{}: not a P-256 public key", path.display()))
            })?;
            Ok(k)
        })
        .collect()
}

/// Why a notice was refused. Each names the fault or the attack.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NoticeError {
    /// Not a well-formed notice.
    #[error("not a well-formed release notice: {0}")]
    Malformed(String),
    /// No key signed it that this machine trusts.
    #[error("the release notice is not signed by a key this machine trusts")]
    BadSignature,
    /// This machine trusts no key for notices.
    #[error("no key is trusted for release notices")]
    NoKeys,
    /// The notice is for another channel.
    #[error("the notice is for channel {got:?}, this machine follows {want:?}")]
    WrongChannel {
        /// Channel named by the notice.
        got: String,
        /// Channel this machine follows.
        want: String,
    },
    /// The notice's expiry has passed.
    #[error("the notice expired at {expired_ms} (now {now_ms})")]
    Expired {
        /// Unix milliseconds of the expiry.
        expired_ms: u64,
        /// Unix milliseconds of the local clock.
        now_ms: u64,
    },
    /// The notice was issued in the future.
    #[error("the notice was issued in the future (clock skew over {} s)", MAX_CLOCK_SKEW_MS / 1000)]
    IssuedInFuture,
    /// The notice names a release older than the one running.
    #[error(
        "the notice names release {version}, older than the running {running}: refusing a downgrade"
    )]
    Downgrade {
        /// Release the notice names.
        version: String,
        /// Release this machine runs.
        running: String,
    },
    /// A newer notice is already held.
    #[error("a newer notice ({have}) is already held; refusing {got}")]
    Superseded {
        /// The notice held.
        have: String,
        /// The notice offered.
        got: String,
    },
}

fn malformed(why: impl fmt::Display) -> NoticeError {
    NoticeError::Malformed(why.to_string())
}

/// `major.minor.patch`, digits only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(pub u64, pub u64, pub u64);

impl FromStr for Version {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let bad = || format!("{s:?} is not major.minor.patch");
        let mut it = s.split('.');
        let mut n = || -> Result<u64, String> {
            let p = it.next().ok_or_else(bad)?;
            if p.is_empty() || p.len() > 9 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad());
            }
            p.parse().map_err(|_| bad())
        };
        let v = Version(n()?, n()?, n()?);
        if it.next().is_some() {
            return Err(bad());
        }
        Ok(v)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// How urgent an update is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "level", rename_all = "snake_case")]
pub enum Severity {
    /// An ordinary release.
    Normal,
    /// The release fixes a security problem.
    Security,
    /// A node must run the release by the start of this epoch.
    RequiredByEpoch {
        /// First epoch for which the release is required.
        epoch: u64,
    },
}

impl Severity {
    /// The level as a lowercase word, as status output and the RPC state it.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Security => "security",
            Self::RequiredByEpoch { .. } => "required_by_epoch",
        }
    }
}

/// One platform's archive: what to download and what it must hash to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformArchive {
    /// `<arch>-<os>`, e.g. `x86_64-linux`.
    pub platform: String,
    /// The archive's file name under the manifest location.
    pub archive: String,
    /// Lowercase hex SHA-256 of the archive.
    pub sha256: String,
    /// Archive size in bytes.
    pub size: u64,
}

/// The signed payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notice {
    /// Always `notice`.
    pub kind: String,
    /// Always [`SPEC`].
    pub spec: String,
    /// The release channel this notice speaks for.
    pub channel: String,
    /// The release, `major.minor.patch`.
    pub version: String,
    /// The oldest release that stays compatible with the network.
    pub min_compatible: String,
    /// When the release was made, Unix milliseconds.
    pub released_ms: u64,
    /// When this notice was signed, Unix milliseconds. Of two notices for one
    /// release the later one wins.
    pub issued_ms: u64,
    /// After this a node ignores the notice, Unix milliseconds.
    pub expires_ms: u64,
    /// How urgent the update is.
    pub severity: Severity,
    /// Plain-text release notes.
    pub notes: String,
    /// A web page with the full notes (https), or empty.
    #[serde(default)]
    pub notes_url: String,
    /// Where the signed manifest lives: the channel's base URL (https).
    pub manifest_url: String,
    /// A digest and size per platform archive.
    pub platforms: Vec<PlatformArchive>,
}

fn plain_text(s: &str) -> bool {
    s.chars().all(|c| c == '\n' || c == '\t' || !c.is_control())
}

fn https_url(s: &str) -> bool {
    s.len() <= 512
        && s.starts_with("https://")
        && s.len() > 8
        && s.bytes().all(|b| b.is_ascii_graphic())
}

impl Notice {
    /// The release as a [`Version`].
    pub fn release(&self) -> Version {
        self.version
            .parse()
            .expect("a checked notice names a release")
    }

    /// The sort key between notices: release first, then when it was signed.
    pub fn order(&self) -> (Version, u64) {
        (self.release(), self.issued_ms)
    }

    /// The archive for `platform`, if the notice lists one.
    pub fn archive_for(&self, platform: &str) -> Option<&PlatformArchive> {
        self.platforms.iter().find(|p| p.platform == platform)
    }

    /// Shape checks. A notice is data: plain text and https links only.
    pub fn check_shape(&self) -> Result<(), NoticeError> {
        if self.kind != "notice" || self.spec != SPEC {
            return Err(malformed(format!("expected kind notice and spec {SPEC}")));
        }
        let channel_ok = !self.channel.is_empty()
            && self.channel.len() <= 32
            && self
                .channel
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !channel_ok {
            return Err(malformed("channel"));
        }
        let v: Version = self.version.parse().map_err(malformed)?;
        let m: Version = self.min_compatible.parse().map_err(malformed)?;
        if m > v {
            return Err(malformed("min_compatible is above version"));
        }
        if self.notes.chars().count() > MAX_NOTES_CHARS || !plain_text(&self.notes) {
            return Err(malformed(
                "notes must be plain text of at most 2000 characters",
            ));
        }
        if !(self.notes_url.is_empty() || https_url(&self.notes_url))
            || !https_url(&self.manifest_url)
        {
            return Err(malformed("links must be https URLs"));
        }
        if self.issued_ms >= self.expires_ms || self.expires_ms - self.issued_ms > MAX_LIFETIME_MS {
            return Err(malformed("expiry must follow issue and be within 180 days"));
        }
        if self.platforms.is_empty() || self.platforms.len() > MAX_PLATFORMS {
            return Err(malformed("platforms"));
        }
        for p in &self.platforms {
            let name_ok = !p.archive.is_empty()
                && p.archive.len() <= 128
                && !p.archive.starts_with('.')
                && p.archive
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
            let platform_ok = !p.platform.is_empty()
                && p.platform.len() <= 32
                && p.platform
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
            let digest_ok = p.sha256.len() == 64
                && p.sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            if !name_ok || !platform_ok || !digest_ok || p.size == 0 || p.size > MAX_ARCHIVE_BYTES {
                return Err(malformed(format!("platform entry {:?}", p.platform)));
            }
        }
        Ok(())
    }
}

/// The signed envelope.
#[derive(Debug, Serialize, Deserialize)]
pub struct Envelope {
    /// Base64 of the exact bytes that were signed.
    pub payload: String,
    /// Signatures over `domain || payload`.
    pub signatures: Vec<Signature>,
}

/// One signature in an [`Envelope`].
#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    /// Hex SHA-256 of the signer's uncompressed SEC1 public key.
    pub keyid: String,
    /// ECDSA P-256 over SHA-256(`domain || payload`): hex raw `r || s` or hex DER.
    pub sig: String,
}

/// Hex SHA-256 of an uncompressed SEC1 public key.
pub fn key_id(sec1: &[u8]) -> String {
    hex::encode(Sha256::digest(sec1))
}

/// Raw 64-byte `r || s` from hex raw, hex DER, or base64 DER.
pub fn signature_bytes(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    let raw = hex::decode(text)
        .ok()
        .or_else(|| base64::engine::general_purpose::STANDARD.decode(text).ok())?;
    if raw.len() == 64 {
        return Some(raw);
    }
    p256::ecdsa::Signature::from_der(&raw)
        .ok()
        .map(|s| s.to_bytes().to_vec())
}

fn verify_prehash(sec1: &[u8], message: &[u8], sig: &[u8]) -> bool {
    let digest: [u8; 32] = Sha256::digest(message).into();
    let Ok(vk) = p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1) else {
        return false;
    };
    let Ok(sig) = p256::ecdsa::Signature::from_slice(sig) else {
        return false;
    };
    vk.verify_prehash(&digest, &sig.normalize_s()).is_ok()
}

/// The bytes a signer signs for `payload`: the domain, then the payload.
/// The release signing run signs this file with the release key.
pub fn signing_message(payload: &[u8]) -> Vec<u8> {
    let mut m = DOMAIN.to_vec();
    m.extend_from_slice(payload);
    m
}

/// Builds the envelope for `payload` from a signature made elsewhere over
/// [`signing_message`], and checks it against `public_sec1` before returning it.
pub fn assemble(
    payload: &[u8],
    public_sec1: &[u8],
    signature: &str,
) -> Result<Vec<u8>, NoticeError> {
    let sig = signature_bytes(signature)
        .ok_or_else(|| malformed("the signature is not raw, DER or base64 DER"))?;
    if !verify_prehash(public_sec1, &signing_message(payload), &sig) {
        return Err(NoticeError::BadSignature);
    }
    let env = Envelope {
        payload: base64::engine::general_purpose::STANDARD.encode(payload),
        signatures: vec![Signature {
            keyid: key_id(public_sec1),
            sig: hex::encode(sig),
        }],
    };
    serde_json::to_vec_pretty(&env).map_err(malformed)
}

/// A P-256 key held in memory, for tests and the rehearsal of the release
/// process. The release key is never held this way.
pub struct LocalKey(p256::ecdsa::SigningKey);

impl LocalKey {
    /// A key from a 32-byte scalar.
    pub fn from_bytes(scalar: &[u8; 32]) -> Result<Self, NoticeError> {
        p256::ecdsa::SigningKey::from_slice(scalar)
            .map(Self)
            .map_err(|_| malformed("not a P-256 scalar"))
    }

    /// A key from a PKCS#8 PEM private key.
    pub fn from_pem(pem: &str) -> Result<Self, NoticeError> {
        use p256::pkcs8::DecodePrivateKey;
        p256::ecdsa::SigningKey::from_pkcs8_pem(pem)
            .map(Self)
            .map_err(|e| malformed(format!("private key: {e}")))
    }

    /// The private key as PKCS#8 PEM, for a test key file.
    pub fn to_pem(&self) -> String {
        use p256::pkcs8::EncodePrivateKey;
        self.0
            .to_pkcs8_pem(Default::default())
            .expect("a P-256 key encodes")
            .to_string()
    }

    /// The uncompressed SEC1 public key.
    pub fn public_sec1(&self) -> Vec<u8> {
        self.0
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec()
    }

    /// Whether this is the embedded release key's pair. Such a key is refused
    /// by the publisher command: the release key signs only in the release signing run.
    pub fn is_release_key(&self) -> bool {
        self.public_sec1() == release_key_sec1()
    }

    /// Signs `payload` and returns the envelope bytes.
    pub fn sign(&self, payload: &[u8]) -> Vec<u8> {
        let digest: [u8; 32] = Sha256::digest(signing_message(payload)).into();
        let sig: p256::ecdsa::Signature = self
            .0
            .sign_prehash(&digest)
            .expect("signing a digest succeeds");
        assemble(payload, &self.public_sec1(), &hex::encode(sig.to_bytes()))
            .expect("a fresh signature verifies")
    }
}

/// What a node checks a notice against.
pub struct Policy<'a> {
    /// Trusted public keys, uncompressed SEC1.
    pub keys: &'a [Vec<u8>],
    /// The channel this node follows.
    pub channel: &'a str,
    /// The release this node runs.
    pub running: Version,
    /// The local clock, Unix milliseconds.
    pub now_ms: u64,
}

/// Verifies signed notice bytes: size, signature, shape, channel, dates and
/// downgrade. Nothing is read or written besides `bytes`.
pub fn verify(bytes: &[u8], policy: &Policy<'_>) -> Result<Notice, NoticeError> {
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(malformed("larger than a notice may be"));
    }
    if policy.keys.is_empty() {
        return Err(NoticeError::NoKeys);
    }
    let env: Envelope = serde_json::from_slice(bytes).map_err(malformed)?;
    let payload = base64::engine::general_purpose::STANDARD
        .decode(&env.payload)
        .map_err(malformed)?;
    let message = signing_message(&payload);
    let signed = env.signatures.iter().any(|s| {
        policy.keys.iter().any(|k| {
            key_id(k) == s.keyid
                && signature_bytes(&s.sig).is_some_and(|sig| verify_prehash(k, &message, &sig))
        })
    });
    if !signed {
        return Err(NoticeError::BadSignature);
    }
    let notice: Notice = serde_json::from_slice(&payload).map_err(malformed)?;
    notice.check_shape()?;
    if notice.channel != policy.channel {
        return Err(NoticeError::WrongChannel {
            got: notice.channel,
            want: policy.channel.to_string(),
        });
    }
    if notice.expires_ms <= policy.now_ms {
        return Err(NoticeError::Expired {
            expired_ms: notice.expires_ms,
            now_ms: policy.now_ms,
        });
    }
    if notice.issued_ms > policy.now_ms + MAX_CLOCK_SKEW_MS {
        return Err(NoticeError::IssuedInFuture);
    }
    if notice.release() < policy.running {
        return Err(NoticeError::Downgrade {
            version: notice.version,
            running: policy.running.to_string(),
        });
    }
    Ok(notice)
}

/// Fixtures for tests in this crate and others.
#[cfg(any(test, feature = "fixture"))]
pub mod fixture {
    use super::*;

    /// A fixed local test key.
    pub fn key(seed: u8) -> LocalKey {
        let mut scalar = [0u8; 32];
        scalar[0] = 0x21;
        scalar[31] = seed.max(1);
        LocalKey::from_bytes(&scalar).unwrap()
    }

    /// The clock the fixtures use.
    pub const NOW: u64 = 1_900_000_000_000;

    /// A valid notice for `version` on the stable channel.
    pub fn notice(version: &str, severity: Severity) -> Notice {
        Notice {
            kind: "notice".into(),
            spec: SPEC.into(),
            channel: "stable".into(),
            version: version.into(),
            min_compatible: "0.2.0".into(),
            released_ms: NOW - 3_600_000,
            issued_ms: NOW - 1_800_000,
            expires_ms: NOW + 30 * 24 * 3_600_000,
            severity,
            notes: "Fixes a checkpoint submission stall.".into(),
            notes_url: "https://tenzro.com/releases/notes".into(),
            manifest_url: "https://downloads.tenzro.com/update/stable".into(),
            platforms: vec![PlatformArchive {
                platform: "x86_64-linux".into(),
                archive: format!("tenzro-{version}-x86_64-linux.tar.gz"),
                sha256: "ab".repeat(32),
                size: 123_456_789,
            }],
        }
    }

    /// `notice` signed with `key`.
    pub fn signed(key: &LocalKey, n: &Notice) -> Vec<u8> {
        key.sign(&serde_json::to_vec(n).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::*;
    use super::*;

    fn policy<'a>(keys: &'a [Vec<u8>], running: &str) -> Policy<'a> {
        Policy {
            keys,
            channel: "stable",
            running: running.parse().unwrap(),
            now_ms: NOW,
        }
    }

    #[test]
    fn a_valid_notice_is_accepted_under_each_severity() {
        let k = key(1);
        let keys = vec![k.public_sec1()];
        for sev in [
            Severity::Normal,
            Severity::Security,
            Severity::RequiredByEpoch { epoch: 40 },
        ] {
            let n = notice("0.2.2", sev);
            let got = verify(&signed(&k, &n), &policy(&keys, "0.2.1")).unwrap();
            assert_eq!(got, n);
        }
    }

    #[test]
    fn a_tampered_notice_is_refused() {
        let k = key(1);
        let keys = vec![k.public_sec1()];
        let mut env: Envelope =
            serde_json::from_slice(&signed(&k, &notice("0.2.2", Severity::Normal))).unwrap();
        // Change a signed byte: the version in the payload.
        let mut payload = base64::engine::general_purpose::STANDARD
            .decode(&env.payload)
            .unwrap();
        let at = payload.windows(5).position(|w| w == b"0.2.2").unwrap();
        payload[at + 4] = b'3';
        env.payload = base64::engine::general_purpose::STANDARD.encode(&payload);
        let err = verify(&serde_json::to_vec(&env).unwrap(), &policy(&keys, "0.2.1")).unwrap_err();
        assert_eq!(err, NoticeError::BadSignature);
    }

    #[test]
    fn an_unsigned_notice_or_one_signed_by_another_key_is_refused() {
        let k = key(1);
        let keys = vec![k.public_sec1()];
        let env = Envelope {
            payload: base64::engine::general_purpose::STANDARD
                .encode(serde_json::to_vec(&notice("0.2.2", Severity::Normal)).unwrap()),
            signatures: vec![],
        };
        assert_eq!(
            verify(&serde_json::to_vec(&env).unwrap(), &policy(&keys, "0.2.1")).unwrap_err(),
            NoticeError::BadSignature
        );
        let other = signed(&key(2), &notice("0.2.2", Severity::Normal));
        assert_eq!(
            verify(&other, &policy(&keys, "0.2.1")).unwrap_err(),
            NoticeError::BadSignature
        );
        assert_eq!(
            verify(&other, &policy(&[], "0.2.1")).unwrap_err(),
            NoticeError::NoKeys
        );
    }

    #[test]
    fn an_expired_notice_is_refused() {
        let k = key(1);
        let keys = vec![k.public_sec1()];
        let mut n = notice("0.2.2", Severity::Normal);
        n.expires_ms = NOW - 1;
        n.issued_ms = NOW - 1000;
        let err = verify(&signed(&k, &n), &policy(&keys, "0.2.1")).unwrap_err();
        assert!(matches!(err, NoticeError::Expired { .. }), "{err}");
    }

    #[test]
    fn an_older_release_than_the_running_one_is_a_downgrade() {
        let k = key(1);
        let keys = vec![k.public_sec1()];
        let err = verify(
            &signed(&k, &notice("0.2.0", Severity::Normal)),
            &policy(&keys, "0.2.1"),
        )
        .unwrap_err();
        assert!(matches!(err, NoticeError::Downgrade { .. }), "{err}");
        // The running release itself is valid: it simply offers nothing.
        verify(
            &signed(&k, &notice("0.2.1", Severity::Normal)),
            &policy(&keys, "0.2.1"),
        )
        .unwrap();
    }

    #[test]
    fn a_notice_for_another_channel_is_refused() {
        let k = key(1);
        let keys = vec![k.public_sec1()];
        let mut n = notice("0.2.2", Severity::Normal);
        n.channel = "security".into();
        let err = verify(&signed(&k, &n), &policy(&keys, "0.2.1")).unwrap_err();
        assert!(matches!(err, NoticeError::WrongChannel { .. }), "{err}");
    }

    #[test]
    fn a_notice_issued_in_the_future_is_refused() {
        let k = key(1);
        let keys = vec![k.public_sec1()];
        let mut n = notice("0.2.2", Severity::Normal);
        n.issued_ms = NOW + MAX_CLOCK_SKEW_MS + 1;
        n.expires_ms = n.issued_ms + 1000;
        assert_eq!(
            verify(&signed(&k, &n), &policy(&keys, "0.2.1")).unwrap_err(),
            NoticeError::IssuedInFuture
        );
    }

    #[test]
    fn a_notice_carries_data_only() {
        let k = key(1);
        let keys = vec![k.public_sec1()];
        let mut bad = Vec::new();
        let mut n = notice("0.2.2", Severity::Normal);
        n.notes = "run \u{1b}[2J this".into();
        bad.push(n);
        let mut n = notice("0.2.2", Severity::Normal);
        n.manifest_url = "http://downloads.tenzro.com/update/stable".into();
        bad.push(n);
        let mut n = notice("0.2.2", Severity::Normal);
        n.notes_url = "javascript:alert(1)".into();
        bad.push(n);
        let mut n = notice("0.2.2", Severity::Normal);
        n.platforms[0].archive = "../../etc/passwd".into();
        bad.push(n);
        let mut n = notice("0.2.2", Severity::Normal);
        n.platforms[0].sha256 = "xyz".into();
        bad.push(n);
        for n in bad {
            assert!(
                matches!(
                    verify(&signed(&k, &n), &policy(&keys, "0.2.1")),
                    Err(NoticeError::Malformed(_))
                ),
                "{n:?}"
            );
        }
    }

    #[test]
    fn a_signature_made_elsewhere_over_the_signing_message_assembles() {
        let k = key(1);
        let payload = serde_json::to_vec(&notice("0.2.2", Severity::Security)).unwrap();
        // What the release signing run does: sign the message file, hand back DER in base64.
        let digest: [u8; 32] = Sha256::digest(signing_message(&payload)).into();
        let sig: p256::ecdsa::Signature = k.0.sign_prehash(&digest).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_der().as_bytes());
        let env = assemble(&payload, &k.public_sec1(), &b64).unwrap();
        verify(&env, &policy(&[k.public_sec1()], "0.2.1")).unwrap();
        assert_eq!(
            assemble(&payload, &key(2).public_sec1(), &b64).unwrap_err(),
            NoticeError::BadSignature
        );
    }

    #[test]
    fn the_embedded_key_is_the_installers() {
        assert!(
            release_key_fingerprint().starts_with("c88aaee7"),
            "{}",
            release_key_fingerprint()
        );
        let installer = include_str!("../../../scripts/install/install.sh");
        let body = RELEASE_KEY_SPKI_PEM.lines().nth(1).unwrap();
        assert!(
            installer.contains(body),
            "the embedded release key differs from install.sh"
        );
        assert!(!key(1).is_release_key());
    }

    #[test]
    fn trusted_keys_default_to_the_release_key_and_a_file_replaces_it() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(trusted_keys(d.path()).unwrap(), vec![release_key_sec1()]);
        std::fs::create_dir_all(d.path().join("update")).unwrap();
        let k = key(9);
        std::fs::write(
            d.path().join("update/trusted-keys.json"),
            format!(
                r#"{{"targets":["{}"],"timestamp":[]}}"#,
                hex::encode(k.public_sec1())
            ),
        )
        .unwrap();
        assert_eq!(trusted_keys(d.path()).unwrap(), vec![k.public_sec1()]);
    }
}
