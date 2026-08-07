//! One root, resolved once, for everything Tenzro puts on disk.
//!
//! # Why this module exists
//!
//! Before it, every call site decided for itself. The CLI downloaded GGUFs to
//! `~/.tenzro/models`; the node served them from `<data_dir>/models` and
//! papered over the gap with three separate hand-rolled `$HOME/.tenzro/models`
//! fallback probes; the desktop app pointed its node at `~/.tenzro/control` and
//! its model list at `~/.tenzro/models`, so the thing you downloaded and the
//! thing you could see were different directories. `NodeConfig::default()` used
//! `./data/user` — relative to whatever the working directory happened to be —
//! while `tenzro-node init` wrote keys to `./data`, so initialising and then
//! starting in the default configuration put the keys somewhere the node did
//! not look. `tenzro node start` defaulted to the string `"~/.tenzro/data"`,
//! which nothing expanded, so it created a directory literally named `~` in the
//! current folder.
//!
//! Fifteen inlined `dirs::home_dir()` calls and ten inlined `env::var("HOME")`
//! calls, between them using four different fallbacks (`"."`, `"/"`, `"/tmp"`,
//! `"/home/tenzro"`) when the home directory could not be found. The result was
//! a machine accumulating half-populated model caches and orphaned RocksDB
//! directories in whatever folder someone last ran a command from, with no way
//! to say where "the" Tenzro data lived.
//!
//! # The rule
//!
//! There is exactly one root, [`tenzro_home`]:
//!
//! 1. `$TENZRO_HOME` if set and non-empty (tilde-expanded).
//! 2. Otherwise `$HOME/.tenzro`.
//!
//! Everything else in this module is a fixed path *under* that root. Nothing
//! outside this module should join a Tenzro path onto a home directory, and
//! nothing should default a path relative to the current working directory.
//!
//! # Shared versus per-instance
//!
//! Two kinds of state, and the distinction is what makes several instances on
//! one machine work:
//!
//! - **Shared** — large, content-addressed, and identical for every instance:
//!   model weights ([`models_dir`]), the HuggingFace cache ([`hf_cache_dir`]),
//!   trainer dataset shards ([`trainer_cache_dir`]). Two nodes on one box
//!   should not download the same 40 GB of weights twice, and they do not have
//!   to, because none of this is instance state.
//! - **Per-instance** — RocksDB, node keys, snapshots, agent memory. These go
//!   under [`instance_data_dir`], which namespaces by instance name, because
//!   two nodes genuinely cannot share a RocksDB directory: the second one to
//!   start is refused by the single-instance lock.
//! - **Per-identity** — everything tied to *who* rather than to *which machine*:
//!   bound devices, sessions, chat transcripts, passkey material. These go under
//!   [`identity_dir`], namespaced by DID.
//!
//! # Why identity state is not machine state
//!
//! A machine hosts identities; it does not own them. One box may run a human's
//! identity and several agents it controls, and the same human may appear on
//! another machine tomorrow. Chat history and passkey material filed at machine
//! level answer "what happened on this box", which is never the question asked
//! of them — the question is always "what did *this identity* do". Filing them
//! under the identity also means revoking or exporting an identity is a
//! directory operation rather than a grep.
//!
//! [`default_data_dir`] is `instance_data_dir("default")`, so a single-node
//! machine never has to think about the distinction.
//!
//! # Escape hatches that remain
//!
//! `--data-dir` still overrides the per-instance directory, and
//! `models_dir` in the node config still overrides the shared model store.
//! Operators who put weights on a separate NVMe or run out of `/var/lib/tenzro`
//! need that. What is gone is the *implicit* divergence — with no flags set,
//! every Tenzro process on a machine now resolves to the same place.

use std::path::{Path, PathBuf};

/// Environment variable naming the Tenzro root. Takes precedence over `$HOME`.
///
/// Set this to run an isolated Tenzro install — a second testnet, a scratch
/// environment, a per-user install on a shared box — without any other flags.
/// Everything below moves with it, which is the point: overriding one path and
/// not the rest is how the scatter started.
pub const TENZRO_HOME_ENV: &str = "TENZRO_HOME";

/// Directory name under `$HOME` when `$TENZRO_HOME` is unset.
pub const DEFAULT_HOME_DIR_NAME: &str = ".tenzro";

/// Instance name used when none is given.
pub const DEFAULT_INSTANCE: &str = "default";

/// Expand a leading `~` or `~/` against `$HOME`.
///
/// A path that came from a config file, a CLI flag, or an interactive prompt
/// may carry a tilde the shell never got a chance to expand — the shell only
/// expands unquoted tildes it parses itself, and `--data-dir=~/x` inside a
/// systemd unit or a quoted argument reaches the process verbatim. Left alone,
/// that creates a directory named `~`.
///
/// Only a leading `~` is expanded, and only when it is the whole component.
/// `~user` is not resolved — that needs passwd lookups this crate has no
/// business doing — and is returned unchanged rather than guessed at.
pub fn expand_tilde(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();
    let Some(s) = path.to_str() else {
        return path.to_path_buf();
    };
    if s == "~" {
        return home_dir().unwrap_or_else(|| PathBuf::from(s));
    }
    let Some(rest) = s.strip_prefix("~/") else {
        return path.to_path_buf();
    };
    match home_dir() {
        Some(home) => home.join(rest),
        None => path.to_path_buf(),
    }
}

/// The user's home directory, or `None`.
///
/// Deliberately not falling back to `"."`, `"/"`, or `"/tmp"` the way the
/// call sites this module replaced each did. A wrong home directory does not
/// fail — it succeeds against the wrong files, quietly, and the four different
/// fallbacks meant four different wrong answers on the same machine. Callers
/// that need a root call [`tenzro_home`], which reports the failure.
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            // Windows has no HOME; USERPROFILE is the equivalent. Tenzro
            // targets Linux and macOS, but the CLI and desktop app are
            // portable enough that failing here would be gratuitous.
            std::env::var_os("USERPROFILE")
                .filter(|h| !h.is_empty())
                .map(PathBuf::from)
        })
}

/// Error resolving the Tenzro root.
#[derive(Debug, thiserror::Error)]
pub enum PathError {
    /// Neither `$TENZRO_HOME` nor `$HOME` is set.
    #[error(
        "cannot locate the Tenzro root: neither ${TENZRO_HOME_ENV} nor $HOME is set. \
         Set {TENZRO_HOME_ENV} to the directory Tenzro should keep its models, keys, \
         and data in."
    )]
    NoHome,

    /// The root exists but could not be created or written to.
    #[error("cannot create Tenzro directory {path}: {source}")]
    Create {
        /// The directory that could not be created.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
}

/// The one Tenzro root: `$TENZRO_HOME`, else `$HOME/.tenzro`.
///
/// Does not create the directory — see [`ensure_dir`]. Read-only callers
/// (listing models, probing for a key) should not bring a directory into
/// existence as a side effect of looking.
pub fn try_tenzro_home() -> Result<PathBuf, PathError> {
    if let Some(v) = std::env::var_os(TENZRO_HOME_ENV)
        && !v.is_empty()
    {
        return Ok(expand_tilde(PathBuf::from(v)));
    }
    home_dir()
        .map(|h| h.join(DEFAULT_HOME_DIR_NAME))
        .ok_or(PathError::NoHome)
}

/// [`try_tenzro_home`], panicking if the root cannot be resolved.
///
/// For binaries and startup paths where there is no useful way to continue: a
/// process that cannot say where its data lives has nothing to do next, and
/// the panic message names the variable to set. Library code on a path that
/// can report an error should use [`try_tenzro_home`].
pub fn tenzro_home() -> PathBuf {
    try_tenzro_home().unwrap_or_else(|e| panic!("{e}"))
}

/// Shared model store — GGUF weights, ONNX bundles, sealed model shards.
///
/// **Shared across every instance on the machine, by design.** Weights are
/// content-addressed and read-only once written; giving each node its own copy
/// would multiply tens of gigabytes per instance for nothing. This is the path
/// the CLI downloads into and the node serves from — previously two different
/// directories.
pub fn models_dir() -> PathBuf {
    tenzro_home().join("models")
}

/// HuggingFace cache root, exported to child processes as `HF_HOME`.
///
/// Under the Tenzro root rather than `~/.cache/huggingface` so that a machine's
/// Tenzro footprint is one directory that can be measured, moved, or deleted.
/// [`hf_token_path`] still reads the standard location as a fallback, because a
/// user who already ran `huggingface-cli login` should not have to do it again.
pub fn hf_cache_dir() -> PathBuf {
    tenzro_home().join("hf")
}

/// Path of the HuggingFace token file inside [`hf_cache_dir`].
pub fn hf_token_path() -> PathBuf {
    hf_cache_dir().join("token")
}

/// The standard HuggingFace token path, for reading only.
///
/// Checked after [`hf_token_path`] so an existing `huggingface-cli login` keeps
/// working. Tenzro never writes here.
pub fn external_hf_token_path() -> Option<PathBuf> {
    home_dir().map(|h| h.join(".cache").join("huggingface").join("token"))
}

/// Shared trainer dataset-shard cache.
///
/// Shared for the same reason as [`models_dir`]: shards are content-addressed
/// by digest, so two trainers on one machine deduplicate for free.
pub fn trainer_cache_dir() -> PathBuf {
    tenzro_home().join("trainer-cache")
}

/// Root under which every per-instance data directory lives.
pub fn instances_root() -> PathBuf {
    tenzro_home().join("instances")
}

/// Per-instance data directory: RocksDB, keys, wallets, snapshots, agent
/// memory, iroh blobs.
///
/// Namespaced because these genuinely cannot be shared — the second node to
/// open the same RocksDB directory fails on its lock file. `name` is sanitized
/// to a single path component so an instance name from a config file or a flag
/// cannot escape [`instances_root`].
pub fn instance_data_dir(name: &str) -> PathBuf {
    instances_root().join(sanitize_component(name))
}

/// Data directory for the unnamed instance — what a single-node machine uses.
pub fn default_data_dir() -> PathBuf {
    instance_data_dir(DEFAULT_INSTANCE)
}

/// CLI configuration file (endpoint, tokens, served models).
pub fn cli_config_path() -> PathBuf {
    tenzro_home().join("config.json")
}

/// Root under which every identity's own state lives.
pub fn identities_root() -> PathBuf {
    tenzro_home().join("identities")
}

/// Everything belonging to one identity — human, machine or agent.
///
/// Namespaced by DID rather than by machine, because this is state about *who*,
/// not about *which box*. An agent that moves between hosts takes its directory
/// with it; a machine that hosts three agents keeps them apart without
/// convention.
///
/// The directory name is the DID with path-unsafe characters replaced, plus a
/// short digest of the original. The digest is what makes it injective: `:`
/// collapses to `_` for the filesystem's sake, so `a:b` and `a_b` would
/// otherwise name one directory and two identities would share their sessions
/// and their keys.
pub fn identity_dir(did: &str) -> PathBuf {
    identities_root().join(identity_component(did))
}

/// Live sessions for one identity.
///
/// Under the identity rather than the machine so that revoking an identity, or
/// signing it out everywhere, is one directory — and so a session cannot be
/// silently reused by a different identity on the same host.
pub fn identity_sessions_dir(did: &str) -> PathBuf {
    identity_dir(did).join("sessions")
}

/// Devices bound to one identity — the phones and machines that can
/// authenticate as it.
pub fn identity_devices_dir(did: &str) -> PathBuf {
    identity_dir(did).join("devices")
}

/// Chat transcripts belonging to one identity.
///
/// Identity-scoped rather than machine-scoped: two people using one machine do
/// not share a conversation history, and one person using two machines expects
/// the transcript to follow the identity.
pub fn identity_chat_history_dir(did: &str) -> PathBuf {
    identity_dir(did).join("chat-history")
}

/// ML-DSA passkey companion seeds for one identity.
pub fn identity_passkey_dir(did: &str) -> PathBuf {
    identity_dir(did).join("passkey")
}

/// Sealed hybrid (Ed25519 + ML-DSA-65) keystore for one identity.
pub fn identity_hybrid_key_path(did: &str) -> PathBuf {
    identity_dir(did).join("hybrid_key.json")
}

/// Filesystem-safe, injective directory name for a DID.
///
/// Readable prefix so an operator can see whose directory this is, plus eight
/// hex of `SHA-256(did)` so two DIDs that sanitise to the same string still get
/// two directories. Truncating the readable part keeps the name usable on
/// filesystems with a 255-byte component limit.
fn identity_component(did: &str) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(did.as_bytes());
    let short = hex_prefix(&digest[..4]);
    let mut readable = sanitize_component(did);
    readable.truncate(96);
    format!("{readable}-{short}")
}

/// Lowercase hex of `bytes`, without pulling in a hex dependency for four
/// bytes — `tenzro-types` sits under every other crate, so its dependency set
/// is worth keeping small.
fn hex_prefix(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// MAC key protecting locally-cached wallet state.
pub fn local_state_mac_key_path() -> PathBuf {
    tenzro_home().join("local_state_mac.key")
}

/// Directory holding named local network definitions (`genesis.toml` + data).
pub fn networks_dir() -> PathBuf {
    tenzro_home().join("networks")
}

/// Directory for one named local network.
pub fn network_dir(name: &str) -> PathBuf {
    networks_dir().join(sanitize_component(name))
}

/// Directory for node logs written by the CLI's service wrappers.
pub fn logs_dir() -> PathBuf {
    tenzro_home().join("logs")
}

/// Create `path` and its parents, mapping the failure to [`PathError`].
pub fn ensure_dir(path: &Path) -> Result<(), PathError> {
    std::fs::create_dir_all(path).map_err(|source| PathError::Create {
        path: path.to_path_buf(),
        source,
    })
}

/// Reduce an arbitrary string to one safe path component.
///
/// Instance and network names reach us from config files and command lines.
/// Without this, `--instance ../../etc` writes outside the root, and a name
/// containing a separator silently creates a nested tree that later lookups do
/// not find. Anything outside `[A-Za-z0-9._-]` becomes `_`; leading dots are
/// stripped so `..` cannot survive; an empty result becomes
/// [`DEFAULT_INSTANCE`].
fn sanitize_component(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_start_matches('.').to_string();
    if trimmed.is_empty() {
        DEFAULT_INSTANCE.to_string()
    } else {
        trimmed
    }
}

/// Environment a child process should inherit so it resolves the same root.
///
/// The node spawns a Python trainer; the trainer downloads shards and model
/// weights. Passing the root down explicitly is what stops the child from
/// falling back to `~/.cache/huggingface` and building a second copy of
/// everything in a directory nothing else looks at.
///
/// Returns `(key, value)` pairs to apply with `Command::env`.
pub fn child_env() -> Vec<(String, String)> {
    let home = tenzro_home();
    vec![
        (TENZRO_HOME_ENV.to_string(), home.display().to_string()),
        ("HF_HOME".to_string(), hf_cache_dir().display().to_string()),
        (
            "TENZRO_TRAINER_CACHE".to_string(),
            trainer_cache_dir().display().to_string(),
        ),
    ]
}

#[cfg(test)]
mod identity_path_tests {
    use super::*;

    // These assert on `identity_component`, the pure function, rather than on
    // `identity_dir`. Sibling tests in this module mutate `TENZRO_HOME`
    // process-wide, so any test that calls an env-reading path builder twice
    // and compares the results is racing them — it can observe two different
    // roots and fail for a reason unrelated to what it is checking. Injectivity
    // and determinism are properties of the name derivation, so testing it
    // directly is both race-free and a more precise statement.

    /// The property the digest suffix exists for. `:` has to collapse for the
    /// filesystem's sake, so without it these two DIDs would name one directory
    /// — and two identities would share their sessions and their keys.
    #[test]
    fn dids_that_sanitise_alike_still_get_separate_components() {
        let a = identity_component("did:tenzro:human:a:b");
        let b = identity_component("did:tenzro:human:a_b");
        assert_ne!(a, b, "distinct DIDs must never share a directory name");
    }

    #[test]
    fn one_did_always_resolves_to_one_component() {
        let did = "did:tenzro:machine:64225154-c233-4ac5-bd79-435035d733b6";
        assert_eq!(identity_component(did), identity_component(did));
    }

    /// Readable prefix so an operator can see whose directory this is without
    /// decoding a hash.
    #[test]
    fn the_directory_name_names_the_identity() {
        let name = identity_component("did:tenzro:human:alice");
        assert!(name.starts_with("did_tenzro_human_alice-"), "{name}");
    }

    /// A pathological DID must not produce a component the filesystem refuses.
    #[test]
    fn an_absurdly_long_did_still_yields_a_usable_component() {
        let did = format!("did:tenzro:human:{}", "x".repeat(4_000));
        let name = identity_component(&did);
        assert!(name.len() <= 255, "component was {} bytes", name.len());
    }

    /// Identity state hangs off the identity, never off an instance — that is
    /// the whole distinction between "who" and "which machine".
    #[test]
    fn identity_state_is_not_under_any_instance() {
        // Asserted on path *components* rather than an absolute prefix.
        // Sibling tests in this module mutate `TENZRO_HOME` process-wide, so a
        // prefix comparison races them and fails for a reason that has nothing
        // to do with the invariant. The structural claim — identity state lives
        // under `identities/`, never under `instances/` — is what actually
        // matters, and it holds wherever the root happens to be.
        let did = "did:tenzro:human:alice";
        for path in [
            identity_dir(did),
            identity_sessions_dir(did),
            identity_devices_dir(did),
            identity_chat_history_dir(did),
            identity_passkey_dir(did),
            identity_hybrid_key_path(did),
        ] {
            let components: Vec<String> = path
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            assert!(
                components.iter().any(|c| c == "identities"),
                "{} is not under identities/",
                path.display()
            );
            assert!(
                !components.iter().any(|c| c == "instances"),
                "{} was filed under an instance",
                path.display()
            );
        }
    }

    /// Each kind of identity state has exactly one home, so nothing is written
    /// to two places and read from one.
    /// Compared by trailing component rather than by whole path, so a sibling
    /// test flipping `TENZRO_HOME` between these calls cannot make two
    /// genuinely distinct homes look distinct for the wrong reason.
    #[test]
    fn each_kind_of_identity_state_has_one_distinct_home() {
        let did = "did:tenzro:agent:bob";
        let leaves: Vec<String> = [
            identity_sessions_dir(did),
            identity_devices_dir(did),
            identity_chat_history_dir(did),
            identity_passkey_dir(did),
            identity_hybrid_key_path(did),
        ]
        .iter()
        .map(|p| {
            p.file_name()
                .expect("a trailing component")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
        let unique: std::collections::BTreeSet<&String> = leaves.iter().collect();
        assert_eq!(unique.len(), leaves.len(), "two kinds shared a path");
    }

    #[test]
    fn two_identities_on_one_machine_do_not_share_state() {
        assert_ne!(
            identity_component("did:tenzro:human:alice"),
            identity_component("did:tenzro:agent:bob")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `$TENZRO_HOME` wins, and every derived path moves with it. A root that
    /// only some paths honour is the failure this module exists to prevent.
    #[test]
    fn tenzro_home_env_overrides_and_carries_every_path() {
        temp_env("/srv/tenzro-a", || {
            let root = PathBuf::from("/srv/tenzro-a");
            assert_eq!(tenzro_home(), root);
            assert_eq!(models_dir(), root.join("models"));
            assert_eq!(hf_cache_dir(), root.join("hf"));
            assert_eq!(trainer_cache_dir(), root.join("trainer-cache"));
            assert_eq!(
                default_data_dir(),
                root.join("instances").join(DEFAULT_INSTANCE)
            );
            assert_eq!(cli_config_path(), root.join("config.json"));
        });
    }

    /// An empty `$TENZRO_HOME` is unset, not a root of `""` — otherwise
    /// `TENZRO_HOME= tenzro ...` would resolve every path to the filesystem
    /// root's relative neighbourhood.
    #[test]
    fn empty_env_falls_through_to_home() {
        temp_env("", || {
            let expected = home_dir().map(|h| h.join(DEFAULT_HOME_DIR_NAME));
            assert_eq!(try_tenzro_home().ok(), expected);
        });
    }

    /// A name from a flag or config file cannot escape the instances root.
    #[test]
    fn instance_names_cannot_escape_the_root() {
        temp_env("/srv/tenzro-b", || {
            let root = PathBuf::from("/srv/tenzro-b").join("instances");
            assert_eq!(instance_data_dir("../../etc"), root.join("_.._etc"));
            assert_eq!(instance_data_dir("a/b"), root.join("a_b"));
            assert_eq!(instance_data_dir(".."), root.join(DEFAULT_INSTANCE));
            assert_eq!(instance_data_dir(""), root.join(DEFAULT_INSTANCE));
            // The ordinary case is untouched.
            assert_eq!(instance_data_dir("validator-0"), root.join("validator-0"));
        });
    }

    /// A tilde that the shell never expanded must not become a directory
    /// named `~`.
    #[test]
    fn tilde_expands_only_when_leading() {
        let home = home_dir().expect("HOME set in test env");
        assert_eq!(expand_tilde("~/.tenzro/data"), home.join(".tenzro/data"));
        assert_eq!(expand_tilde("~"), home);
        // Not a leading component, so not ours to touch.
        assert_eq!(expand_tilde("/opt/~/data"), PathBuf::from("/opt/~/data"));
        assert_eq!(expand_tilde("~user/data"), PathBuf::from("~user/data"));
        assert_eq!(
            expand_tilde("relative/path"),
            PathBuf::from("relative/path")
        );
    }

    /// Children are told the root, not left to guess it.
    #[test]
    fn child_env_carries_the_root_and_the_caches() {
        temp_env("/srv/tenzro-c", || {
            let env = child_env();
            let get = |k: &str| {
                env.iter()
                    .find(|(key, _)| key == k)
                    .map(|(_, v)| v.clone())
                    .unwrap_or_else(|| panic!("{k} missing from child_env"))
            };
            assert_eq!(get(TENZRO_HOME_ENV), "/srv/tenzro-c");
            assert_eq!(get("HF_HOME"), "/srv/tenzro-c/hf");
            assert_eq!(get("TENZRO_TRAINER_CACHE"), "/srv/tenzro-c/trainer-cache");
        });
    }

    /// Set `$TENZRO_HOME` for the duration of `f`, then restore it.
    ///
    /// Serialized on a mutex because the environment is process-global and
    /// these tests share a process. Poisoning is ignored deliberately — a
    /// panic in one test must not cascade into unrelated failures here.
    fn temp_env(value: &str, f: impl FnOnce()) {
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var_os(TENZRO_HOME_ENV);
        // SAFETY: the mutex above serializes every mutation of this variable
        // within the test binary, and nothing else in this crate reads it
        // concurrently.
        unsafe { std::env::set_var(TENZRO_HOME_ENV, value) };
        f();
        unsafe {
            match prior {
                Some(v) => std::env::set_var(TENZRO_HOME_ENV, v),
                None => std::env::remove_var(TENZRO_HOME_ENV),
            }
        }
    }
}
