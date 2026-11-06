//! The operator's own credentials: for model origins, and for the serving
//! endpoint a connector forwards to.
//!
//! An operator with their own Hugging Face account can let their node fetch
//! weights the origin gates behind that account (see
//! [`tenzro_model::origin_credential`]). An operator whose node serves models
//! from an existing OpenAI-compatible endpoint ([`crate::connector`]) gives it
//! that endpoint's API key. `tenzro-node credentials set <huggingface|upstream>`
//! reads the secret from stdin and seals it to the X25519 key this machine's
//! TPM or Secure Enclave derives for its secrets; only the sealed envelope is
//! written, under `<data_dir>/credentials/`. At startup the node opens it.
//! A sealed secret is used first. An operator without a TPM or Secure Enclave,
//! or who keeps secrets outside the node, gives it in the secret's environment
//! variable ([`Secret::env`]) or the configuration file
//! ([`Secret::config_key`]) instead, at their own risk; the environment wins
//! over the file, and the node logs one warning that the secret is unsealed.
//!
//! There is no default credential. A secret stays in this process: it is not
//! logged, sent over RPC, gossiped, written to the chain or put in a receipt.

use std::path::{Path, PathBuf};

use tenzro_crypto::encryption::{EncryptedEnvelope, envelope_decrypt, envelope_encrypt};
use tenzro_crypto::hybrid_seal::HybridRecipient;
use tenzro_keygen::NodeKeys;
use tenzro_model::origin_credential::{self, OriginCredential};
use tracing::warn;
use zeroize::Zeroizing;

/// A secret written in the operator's configuration file. It is never written
/// back out: a config save or export leaves it out, and `Debug` shows only
/// that one is set.
#[derive(Clone)]
pub struct ConfigSecret(Zeroizing<String>);

impl ConfigSecret {
    pub fn new(value: &str) -> Self {
        Self(Zeroizing::new(value.to_string()))
    }
}

impl std::fmt::Debug for ConfigSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConfigSecret(redacted)")
    }
}

impl<'de> serde::Deserialize<'de> for ConfigSecret {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = Zeroizing::new(<String as serde::Deserialize>::deserialize(d)?);
        Ok(Self(s))
    }
}

/// A secret the operator gives their node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Secret {
    /// An access token of the operator's own Hugging Face account.
    Huggingface,
    /// The API key of the endpoint a connector forwards to.
    Upstream,
}

impl Secret {
    fn file_name(self) -> &'static str {
        match self {
            Secret::Huggingface => "huggingface.sealed",
            Secret::Upstream => "upstream.sealed",
        }
    }

    /// The environment variable that carries this secret when the operator
    /// keeps secrets outside the node.
    pub fn env(self) -> &'static str {
        match self {
            Secret::Huggingface => origin_credential::ENV,
            Secret::Upstream => "TENZRO_UPSTREAM_API_KEY",
        }
    }

    /// Where this secret goes in the node's configuration file.
    pub fn config_key(self) -> &'static str {
        match self {
            Secret::Huggingface => "huggingface_credential",
            Secret::Upstream => "[connector] api_key",
        }
    }

    /// The `tenzro-node credentials set` argument for this secret.
    fn origin(self) -> &'static str {
        match self {
            Secret::Huggingface => "huggingface",
            Secret::Upstream => "upstream",
        }
    }
}

/// Accept a secret as the operator typed it, trimmed. Refuses an empty one
/// and one with whitespace or control characters inside it, which no access
/// token or API key has and which could not be sent as a header.
pub fn accept(secret: &str) -> Result<Zeroizing<String>, String> {
    let t = secret.trim();
    if t.is_empty() {
        return Err("the credential is empty".into());
    }
    if t.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("the credential has whitespace or control characters in it".into());
    }
    Ok(Zeroizing::new(t.to_string()))
}

/// Where an installed credential came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialSource {
    SealedStore,
    Environment,
    ConfigFile,
}

/// `secret` given unsealed: from its environment variable, or else from the
/// configuration file.
fn unsealed(
    secret: Secret,
    configured: Option<&ConfigSecret>,
) -> Result<Option<(Zeroizing<String>, CredentialSource)>, String> {
    if let Some(v) = std::env::var_os(secret.env()) {
        let v = Zeroizing::new(v.to_string_lossy().into_owned());
        return accept(&v)
            .map(|v| Some((v, CredentialSource::Environment)))
            .map_err(|e| format!("{}: {e}", secret.env()));
    }
    if let Some(c) = configured {
        return accept(&c.0)
            .map(|v| Some((v, CredentialSource::ConfigFile)))
            .map_err(|e| format!("{} in the configuration file: {e}", secret.config_key()));
    }
    Ok(None)
}

fn sealed_path(data_dir: &Path, secret: Secret) -> PathBuf {
    data_dir.join("credentials").join(secret.file_name())
}

/// Seal `value` to this machine's sealing key and store it as `secret`,
/// replacing whatever was stored for it before.
pub fn seal(
    data_dir: &Path,
    keys: &NodeKeys,
    secret: Secret,
    value: &str,
) -> Result<PathBuf, String> {
    let value = accept(value)?;
    let recipient = keys
        .machine_sealing()
        .map_err(|e| format!("the machine sealing key: {e}"))?;
    let envelope = envelope_encrypt(&recipient.public_key(), value.as_bytes())
        .map_err(|e| format!("sealing the credential: {e}"))?;
    let bytes = serde_json::to_vec(&envelope).map_err(|e| e.to_string())?;
    let path = sealed_path(data_dir, secret);
    let dir = path.parent().expect("a parent");
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let tmp = path.with_extension("sealed.tmp");
    write_private(&tmp, &bytes)?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(bytes)
        .map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| format!("{}: {e}", path.display()))
}

/// The sealed `secret`, opened with this machine's key; `None` when none is
/// stored.
pub fn open(
    data_dir: &Path,
    keys: &NodeKeys,
    secret: Secret,
) -> Result<Option<Zeroizing<String>>, String> {
    let path = sealed_path(data_dir, secret);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let envelope: EncryptedEnvelope =
        serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    let recipient = keys
        .machine_sealing()
        .map_err(|e| format!("the machine sealing key: {e}"))?;
    let plain = zeroize::Zeroizing::new(envelope_decrypt(&recipient, &envelope).map_err(|_| {
        format!(
            "{} does not open with this machine's key; set the credential again on this machine",
            path.display()
        )
    })?);
    let text = std::str::from_utf8(&plain).map_err(|_| format!("{}: not text", path.display()))?;
    accept(text).map(Some)
}

/// Remove the stored `secret`. True when one was stored.
pub fn clear(data_dir: &Path, secret: Secret) -> Result<bool, String> {
    let path = sealed_path(data_dir, secret);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Whether `secret` is sealed in this data directory.
pub fn stored(data_dir: &Path, secret: Secret) -> bool {
    sealed_path(data_dir, secret).exists()
}

/// `secret` from the sealed store when one is sealed; otherwise from its
/// environment variable, or else `configured`, the value in the
/// configuration file. An unsealed secret is used with one warning and never
/// refused. The hardware key is opened only when a sealed secret exists, so a
/// machine without a TPM or Secure Enclave never needs one. The value is
/// never logged or put in an error.
pub fn read(
    data_dir: &Path,
    secret: Secret,
    configured: Option<&ConfigSecret>,
) -> Result<Option<(Zeroizing<String>, CredentialSource)>, String> {
    let sealed_error = if stored(data_dir, secret) {
        let opened = NodeKeys::open(data_dir)
            .map_err(|e| format!("node keys: {e}"))
            .and_then(|keys| open(data_dir, &keys, secret));
        match opened {
            Ok(Some(v)) => return Ok(Some((v, CredentialSource::SealedStore))),
            Ok(None) => None,
            Err(e) => Some(e),
        }
    } else {
        None
    };
    let found = unsealed(secret, configured)?;
    match (&found, sealed_error) {
        (None, Some(e)) => return Err(e),
        (Some(_), Some(e)) => warn!(
            credential = secret.origin(),
            "the sealed credential does not open ({e}); the unsealed one is used"
        ),
        _ => {}
    }
    if let Some((_, source)) = &found {
        warn!(
            credential = secret.origin(),
            ?source,
            "the {} credential is stored unsealed, at the operator's own risk; on a machine \
             with a TPM or Secure Enclave, `tenzro-node credentials set {}` seals it",
            secret.origin(),
            secret.origin()
        );
    }
    Ok(found)
}

/// Each place the node looks for `secret`, in the order [`read`] tries them,
/// and whether a value is there. Never the value.
pub fn sources(
    data_dir: &Path,
    secret: Secret,
    configured: Option<&ConfigSecret>,
) -> Vec<(CredentialSource, bool)> {
    vec![
        (CredentialSource::SealedStore, stored(data_dir, secret)),
        (
            CredentialSource::Environment,
            std::env::var_os(secret.env()).is_some(),
        ),
        (CredentialSource::ConfigFile, configured.is_some()),
    ]
}

fn describe(secret: Secret, source: CredentialSource) -> String {
    match source {
        CredentialSource::SealedStore => "sealed on this machine".to_string(),
        CredentialSource::Environment => format!("environment {}", secret.env()),
        CredentialSource::ConfigFile => format!("config file {}", secret.config_key()),
    }
}

/// What `tenzro-node credentials status` prints for `secret`: the source the
/// node uses, then every source in the order the node tries them, each with
/// whether a value is set and whether it is the one used. `unset` is the
/// first line when none is set. Never the value.
pub fn status(
    data_dir: &Path,
    secret: Secret,
    configured: Option<&ConfigSecret>,
    unset: &str,
) -> String {
    let sources = sources(data_dir, secret, configured);
    let used = sources.iter().find(|(_, set)| *set).map(|(s, _)| *s);
    let mut out = format!(
        "{}: {}",
        secret.origin(),
        match used {
            Some(CredentialSource::SealedStore) => "sealed on this machine".to_string(),
            Some(source) => format!("{} (unsealed)", describe(secret, source)),
            None => unset.to_string(),
        }
    );
    for (i, (source, set)) in sources.iter().enumerate() {
        let state = match (*set, Some(*source) == used) {
            (true, true) => "set, used",
            (true, false) => "set, not used",
            (false, _) => "not set",
        };
        out.push_str(&format!(
            "\n  {}. {}: {state}",
            i + 1,
            describe(secret, *source)
        ));
    }
    out
}

/// Install the operator's Hugging Face credential for this process, as
/// [`read`] finds it: sealed first, else the environment, else `configured`
/// from the configuration file.
pub fn install_operator_credential(
    data_dir: &Path,
    configured: Option<&ConfigSecret>,
) -> Result<Option<CredentialSource>, String> {
    match read(data_dir, Secret::Huggingface, configured)? {
        Some((c, source)) => {
            origin_credential::install(Some(OriginCredential::new(&c)?));
            Ok(Some(source))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};

    /// The tests here set the secrets' process-wide environment variables.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Run `f` with every log line at every level captured.
    fn logged<T>(f: impl FnOnce() -> T) -> (T, String) {
        let buf = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish();
        let out = tracing::subscriber::with_default(subscriber, f);
        let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        (out, text)
    }

    /// With nothing sealed (no hardware key is ever opened, so a machine
    /// without a TPM works), a secret in the environment is used, with one
    /// warning that names the seal command; without it the configuration
    /// file's value is used, and the environment wins over the file. The value
    /// is never in a log line or an error.
    #[test]
    fn an_unsealed_secret_from_env_or_config_is_used_with_one_warning() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let from_config = ConfigSecret::new("upstream-key-in-config");
        // SAFETY: ENV_LOCK serialises every test that touches these variables.
        unsafe {
            std::env::set_var(Secret::Upstream.env(), "upstream-key-in-env");
            std::env::set_var(Secret::Huggingface.env(), "hf-token-in-env");
        }
        let ((upstream, hf), logs) = logged(|| {
            (
                read(dir.path(), Secret::Upstream, Some(&from_config)),
                install_operator_credential(dir.path(), None),
            )
        });
        unsafe {
            std::env::remove_var(Secret::Upstream.env());
            std::env::remove_var(Secret::Huggingface.env());
        }
        let (key, source) = upstream.unwrap().unwrap();
        assert_eq!(key.as_str(), "upstream-key-in-env");
        assert_eq!(source, CredentialSource::Environment);
        assert_eq!(hf.unwrap(), Some(CredentialSource::Environment));
        assert!(origin_credential::installed());
        origin_credential::install(None);
        assert_eq!(logs.matches("stored unsealed").count(), 2, "{logs}");
        assert!(
            logs.contains("tenzro-node credentials set upstream"),
            "{logs}"
        );
        assert!(
            logs.contains("tenzro-node credentials set huggingface"),
            "{logs}"
        );
        for value in [
            "upstream-key-in-env",
            "upstream-key-in-config",
            "hf-token-in-env",
        ] {
            assert!(!logs.contains(value), "the value is never logged: {logs}");
        }

        // No environment: the configuration file's value.
        let (found, logs) = logged(|| read(dir.path(), Secret::Upstream, Some(&from_config)));
        let (key, source) = found.unwrap().unwrap();
        assert_eq!(key.as_str(), "upstream-key-in-config");
        assert_eq!(source, CredentialSource::ConfigFile);
        assert_eq!(logs.matches("stored unsealed").count(), 1, "{logs}");
        assert!(!logs.contains("upstream-key-in-config"), "{logs}");
        assert!(!format!("{from_config:?}").contains("upstream-key-in-config"));

        // A malformed value is reported without echoing it.
        let bad = ConfigSecret::new("bad upstream key");
        let e = read(dir.path(), Secret::Upstream, Some(&bad)).unwrap_err();
        assert!(!e.contains("bad upstream key"), "{e}");

        // Nothing anywhere: nothing used, nothing logged.
        let (found, logs) = logged(|| read(dir.path(), Secret::Upstream, None));
        assert!(found.unwrap().is_none());
        assert!(logs.is_empty(), "{logs}");
    }

    /// `credentials status` lists the sealed store, the environment and the
    /// configuration file in the order the node resolves them, marks the one
    /// it uses, and never prints a value.
    #[test]
    fn credentials_status_lists_every_source_in_resolution_order_and_the_one_used() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let cfg = ConfigSecret::new("upstream-key-in-config");
        let values = [
            "upstream-key-in-config",
            "upstream-key-in-env",
            "upstream-key-sealed",
        ];
        let check = |s: &str| {
            let sealed = s.find("1. sealed on this machine").expect(s);
            let env = s.find("2. environment TENZRO_UPSTREAM_API_KEY").expect(s);
            let file = s.find("3. config file [connector] api_key").expect(s);
            assert!(sealed < env && env < file, "{s}");
            for v in values {
                assert!(!s.contains(v), "a value is never printed: {s}");
            }
        };

        let s = status(dir.path(), Secret::Upstream, None, "not set");
        check(&s);
        assert!(s.starts_with("upstream: not set\n"), "{s}");

        let s = status(dir.path(), Secret::Upstream, Some(&cfg), "not set");
        check(&s);
        assert!(
            s.starts_with("upstream: config file [connector] api_key (unsealed)"),
            "{s}"
        );
        assert!(
            s.contains("3. config file [connector] api_key: set, used"),
            "{s}"
        );

        // SAFETY: ENV_LOCK serialises every test that touches these variables.
        unsafe { std::env::set_var(Secret::Upstream.env(), "upstream-key-in-env") };
        let s = status(dir.path(), Secret::Upstream, Some(&cfg), "not set");
        check(&s);
        assert!(
            s.starts_with("upstream: environment TENZRO_UPSTREAM_API_KEY (unsealed)"),
            "{s}"
        );
        assert!(
            s.contains("2. environment TENZRO_UPSTREAM_API_KEY: set, used"),
            "{s}"
        );
        assert!(
            s.contains("3. config file [connector] api_key: set, not used"),
            "{s}"
        );

        let keys = NodeKeys::open(dir.path()).unwrap();
        seal(dir.path(), &keys, Secret::Upstream, "upstream-key-sealed").unwrap();
        drop(keys);
        let s = status(dir.path(), Secret::Upstream, Some(&cfg), "not set");
        unsafe { std::env::remove_var(Secret::Upstream.env()) };
        check(&s);
        assert!(s.starts_with("upstream: sealed on this machine\n"), "{s}");
        assert!(s.contains("1. sealed on this machine: set, used"), "{s}");
        assert!(
            s.contains("2. environment TENZRO_UPSTREAM_API_KEY: set, not used"),
            "{s}"
        );
    }

    /// A sealed secret is used before the environment and the configuration
    /// file, with no unsealed warning, and none of the values is logged.
    #[test]
    fn a_sealed_secret_wins_over_env_and_config() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let keys = NodeKeys::open(dir.path()).unwrap();
        seal(dir.path(), &keys, Secret::Upstream, "upstream-key-sealed").unwrap();
        drop(keys);
        let from_config = ConfigSecret::new("upstream-key-in-config");
        // SAFETY: ENV_LOCK serialises every test that touches these variables.
        unsafe { std::env::set_var(Secret::Upstream.env(), "upstream-key-in-env") };
        let (found, logs) = logged(|| read(dir.path(), Secret::Upstream, Some(&from_config)));
        unsafe { std::env::remove_var(Secret::Upstream.env()) };
        let (key, source) = found.unwrap().unwrap();
        assert_eq!(key.as_str(), "upstream-key-sealed");
        assert_eq!(source, CredentialSource::SealedStore);
        assert!(!logs.contains("stored unsealed"), "{logs}");
        for value in [
            "upstream-key-sealed",
            "upstream-key-in-env",
            "upstream-key-in-config",
        ] {
            assert!(!logs.contains(value), "the value is never logged: {logs}");
        }
    }

    #[test]
    fn a_sealed_credential_opens_on_its_machine_only_and_is_never_stored_in_clear() {
        let dir = tempfile::tempdir().unwrap();
        let keys = NodeKeys::open(dir.path()).unwrap();
        let path = seal(
            dir.path(),
            &keys,
            Secret::Huggingface,
            "operator-sealed-token-3",
        )
        .unwrap();
        let on_disk = std::fs::read(&path).unwrap();
        assert!(!on_disk.windows(23).any(|w| w == b"operator-sealed-token-3"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let opened = open(dir.path(), &keys, Secret::Huggingface)
            .unwrap()
            .unwrap();
        assert_eq!(opened.as_str(), "operator-sealed-token-3");
        // Each secret has its own envelope.
        assert!(open(dir.path(), &keys, Secret::Upstream).unwrap().is_none());

        // Another machine's key (another test root) cannot open it.
        let other_dir = tempfile::tempdir().unwrap();
        let other = NodeKeys::open(other_dir.path()).unwrap();
        let err = open(dir.path(), &other, Secret::Huggingface).unwrap_err();
        assert!(!err.contains("operator-sealed-token-3"), "{err}");

        assert!(clear(dir.path(), Secret::Huggingface).unwrap());
        assert!(
            open(dir.path(), &keys, Secret::Huggingface)
                .unwrap()
                .is_none()
        );
        assert!(!clear(dir.path(), Secret::Huggingface).unwrap());
    }
}
