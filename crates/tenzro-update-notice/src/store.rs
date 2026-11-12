//! The newest verified notice, kept on disk at `<data_dir>/update/notice.json`.
//!
//! The cache holds the signed bytes exactly as received, so a restart reads
//! them back through the same checks a fresh notice passes: a cached notice
//! that has since expired, or that names a release this machine no longer
//! needs, is not served. Writes go through a temporary file and a rename.

use std::path::{Path, PathBuf};

use crate::notice::{self, Notice, NoticeError, Policy};

/// What [`NoticeStore::offer`] did with a notice that verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Offer {
    /// It is newer than what was held; it is now the cached notice.
    Stored(Notice),
    /// It is the notice already held.
    Known(Notice),
}

/// The notice cache of one node or CLI install.
#[derive(Debug, Clone)]
pub struct NoticeStore {
    path: PathBuf,
}

impl NoticeStore {
    /// The cache under `data_dir`.
    pub fn open(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join("update").join("notice.json"),
        }
    }

    /// The cached signed bytes, unchecked. For serving: callers verify first.
    pub fn raw(&self) -> Option<Vec<u8>> {
        std::fs::read(&self.path).ok()
    }

    /// The cached notice, if it still verifies under `policy`.
    pub fn cached(&self, policy: &Policy<'_>) -> Option<(Notice, Vec<u8>)> {
        let raw = self.raw()?;
        notice::verify(&raw, policy).ok().map(|n| (n, raw))
    }

    /// Verifies `bytes` and keeps them when they are newer than the cached
    /// notice (a later release, or a later signing of the same release). An
    /// older one is refused with [`NoticeError::Superseded`].
    pub fn offer(&self, bytes: &[u8], policy: &Policy<'_>) -> Result<Offer, NoticeError> {
        let offered = notice::verify(bytes, policy)?;
        if let Some((held, _)) = self.cached(policy) {
            if offered.order() < held.order() {
                return Err(NoticeError::Superseded {
                    have: held.version,
                    got: offered.version,
                });
            }
            if offered.order() == held.order() {
                return Ok(Offer::Known(held));
            }
        }
        self.write(bytes)
            .map_err(|e| NoticeError::Malformed(format!("cache the notice: {e}")))?;
        Ok(Offer::Stored(offered))
    }

    /// What the cached notice says, as one JSON object for a reader that is
    /// not the CLI banner: the assistant, the Hub, a script. `update_available`
    /// and the fields next to it are as in [`crate::banner::json_fields`]; the
    /// rest describes the release. When no notice is held, or it no longer
    /// verifies, `update_available` is false and `notice` is null.
    pub fn status(&self, policy: &Policy<'_>) -> serde_json::Value {
        let cached = self.cached(policy).map(|(n, _)| n);
        let mut out = crate::banner::json_fields(cached.as_ref(), policy.running);
        let map = out.as_object_mut().expect("json_fields is an object");
        map.insert("running_version".into(), policy.running.to_string().into());
        map.insert(
            "notice".into(),
            match &cached {
                Some(n) => serde_json::json!({
                    "version": n.version,
                    "channel": n.channel,
                    "min_compatible": n.min_compatible,
                    "released_ms": n.released_ms,
                    "expires_ms": n.expires_ms,
                    "severity": n.severity,
                    "notes": n.notes,
                    "manifest_url": n.manifest_url,
                    "platforms": n.platforms,
                    "below_min_compatible": policy.running < n.min_compatible.parse().unwrap_or(policy.running),
                }),
                None => serde_json::Value::Null,
            },
        );
        out
    }

    fn write(&self, bytes: &[u8]) -> std::io::Result<()> {
        let dir = self.path.parent().expect("the cache path has a parent");
        std::fs::create_dir_all(dir)?;
        let tmp = dir.join("notice.json.tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notice::Severity;
    use crate::notice::fixture::*;

    fn policy<'a>(keys: &'a [Vec<u8>], now_ms: u64) -> Policy<'a> {
        Policy {
            keys,
            channel: "stable",
            running: "0.2.1".parse().unwrap(),
            now_ms,
        }
    }

    #[test]
    fn the_cache_survives_a_restart_and_serves_the_same_bytes() {
        let d = tempfile::tempdir().unwrap();
        let k = key(1);
        let keys = vec![k.public_sec1()];
        let bytes = signed(&k, &notice("0.2.2", Severity::Security));
        assert!(matches!(
            NoticeStore::open(d.path())
                .offer(&bytes, &policy(&keys, NOW))
                .unwrap(),
            Offer::Stored(_)
        ));
        // A new store over the same directory is the node after a restart.
        let after = NoticeStore::open(d.path());
        let (n, raw) = after
            .cached(&policy(&keys, NOW))
            .expect("the cached notice is read back");
        assert_eq!(n.version, "0.2.2");
        assert_eq!(raw, bytes);
    }

    #[test]
    fn a_cached_notice_that_expired_while_the_node_was_down_is_not_served() {
        let d = tempfile::tempdir().unwrap();
        let k = key(1);
        let keys = vec![k.public_sec1()];
        let n = notice("0.2.2", Severity::Normal);
        let expires = n.expires_ms;
        NoticeStore::open(d.path())
            .offer(&signed(&k, &n), &policy(&keys, NOW))
            .unwrap();
        assert!(
            NoticeStore::open(d.path())
                .cached(&policy(&keys, expires + 1))
                .is_none()
        );
    }

    #[test]
    fn only_a_newer_notice_replaces_the_cached_one() {
        let d = tempfile::tempdir().unwrap();
        let k = key(1);
        let keys = vec![k.public_sec1()];
        let s = NoticeStore::open(d.path());
        let p = policy(&keys, NOW);
        let v3 = signed(&k, &notice("0.2.3", Severity::Normal));
        s.offer(&v3, &p).unwrap();
        // An older release, even correctly signed, is refused and the cache is unchanged.
        let err = s
            .offer(&signed(&k, &notice("0.2.2", Severity::Normal)), &p)
            .unwrap_err();
        assert!(matches!(err, NoticeError::Superseded { .. }), "{err}");
        assert_eq!(s.raw().unwrap(), v3);
        assert!(matches!(s.offer(&v3, &p).unwrap(), Offer::Known(_)));
        // The same release signed later (a raised severity) replaces it.
        let mut again = notice("0.2.3", Severity::Security);
        again.issued_ms += 60_000;
        assert!(matches!(
            s.offer(&signed(&k, &again), &p).unwrap(),
            Offer::Stored(_)
        ));
        assert_eq!(s.cached(&p).unwrap().0.severity, Severity::Security);
    }

    #[test]
    fn a_refused_notice_leaves_nothing_on_disk() {
        let d = tempfile::tempdir().unwrap();
        let k = key(1);
        let keys = vec![k.public_sec1()];
        let s = NoticeStore::open(d.path());
        assert!(
            s.offer(
                &signed(&key(2), &notice("0.2.2", Severity::Normal)),
                &policy(&keys, NOW)
            )
            .is_err()
        );
        assert!(s.raw().is_none());
    }

    #[test]
    fn status_is_the_read_function_for_the_assistant() {
        let d = tempfile::tempdir().unwrap();
        let k = key(1);
        let keys = vec![k.public_sec1()];
        let s = NoticeStore::open(d.path());
        let p = policy(&keys, NOW);
        let none = s.status(&p);
        assert_eq!(none["update_available"], false);
        assert!(none["notice"].is_null());
        s.offer(
            &signed(
                &k,
                &notice("0.2.2", Severity::RequiredByEpoch { epoch: 40 }),
            ),
            &p,
        )
        .unwrap();
        let got = s.status(&p);
        assert_eq!(got["update_available"], true);
        assert_eq!(got["latest_version"], "0.2.2");
        assert_eq!(got["running_version"], "0.2.1");
        assert_eq!(got["severity"], "required_by_epoch");
        assert_eq!(got["notice"]["severity"]["epoch"], 40);
        assert_eq!(got["notice"]["platforms"][0]["size"], 123_456_789u64);
        assert_eq!(got["notice"]["below_min_compatible"], false);
    }
}
