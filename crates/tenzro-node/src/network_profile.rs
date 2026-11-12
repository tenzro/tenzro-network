//! The network profile a release ships: where a node that was given no
//! `--boot-nodes` joins the network.
//!
//! A release carries `share/network/<chain_id>.toml` beside `bin/` (the same
//! `$ORIGIN/..` layout the ONNX Runtime libraries use). It names the relay
//! (its URL and its operator's machine identity) and the genesis validators'
//! machine identities. A node started without `--boot-nodes` reads it, so a
//! fresh install joins the network without anyone appending
//! `TENZRO_BOOT_NODES` to its environment by hand.
//!
//! The profile is packaging, not consensus: it is not part of the genesis
//! file, never changes its hash, and holds only what a node needs to find its
//! first peers.
//!
//! ```toml
//! version = 1
//! chain_id = 13380
//!
//! [relay]
//! url = "https://relay.example.net/"
//! operator_did = "did:tenzro:machine:<64 hex>"
//!
//! # More relays, each served by its operator: a node fails over between
//! # them, and a validator that serves one lists it here.
//! [[relays]]
//! url = "https://relay2.example.net/"
//! operator_did = "did:tenzro:machine:<64 hex>"
//!
//! [[validators]]
//! did = "did:tenzro:machine:<64 hex>"
//! # relay = "https://other-relay.example.net/"   # default: [relay].url
//! ```
//!
//! A relay that a validator serves later is learned from the validator's
//! signed endpoint record, so it need not be listed for nodes to use it.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use tenzro_iroh::BootIdentity;
use tenzro_onboarding_types::onboarding::GateMode;

use crate::error::{NodeError, Result};

/// Names a profile file explicitly. A path that does not exist is an error,
/// never silently skipped.
pub const PROFILE_ENV: &str = "TENZRO_NETWORK_PROFILE";

/// The profile format this build reads.
pub const PROFILE_VERSION: u32 = 1;

/// The relay of a profile.
#[derive(Debug, Clone, Deserialize)]
pub struct ProfileRelay {
    /// Where the relay is reached.
    pub url: String,
    /// The machine identity of the relay's operator.
    pub operator_did: String,
}

/// A genesis validator of a profile.
#[derive(Debug, Clone, Deserialize)]
pub struct ProfileValidator {
    /// The validator's machine identity.
    pub did: String,
    /// The relay it is reached through, when not the profile's own.
    #[serde(default)]
    pub relay: Option<String>,
}

/// A network profile.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkProfile {
    /// Format version.
    pub version: u32,
    /// The chain the profile is for.
    pub chain_id: u64,
    /// The relay, when the network has one.
    #[serde(default)]
    pub relay: Option<ProfileRelay>,
    /// Further relays, beside `relay`, each with its operator.
    #[serde(default)]
    pub relays: Vec<ProfileRelay>,
    /// The genesis validators.
    #[serde(default)]
    pub validators: Vec<ProfileValidator>,
    /// The identity gate setting the network ships for its nodes.
    #[serde(default)]
    pub onboarding: Option<ProfileOnboarding>,
    /// The `[state_sync]` table: where a joining node asks for a snapshot.
    #[serde(default)]
    pub state_sync: Option<ProfileStateSync>,
    /// The `[snapshot]` table: how validators of this network cut, keep and
    /// publish snapshots.
    #[serde(default)]
    pub snapshot: Option<ProfileSnapshot>,
}

/// The `[state_sync]` table of a network profile: the snapshot peers a node
/// of this network restores from unless its own config names some.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileStateSync {
    /// Snapshot peers, as `<EndpointId>` or `<EndpointId>@<ip:port>`. Empty,
    /// the node asks the boot identities of the profile.
    #[serde(default)]
    pub from: Vec<String>,
}

/// The `[snapshot]` table of a network profile: the snapshot producer
/// settings the network ships. A key the node config sets itself wins.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSnapshot {
    /// Minimum spacing between snapshots, in blocks.
    #[serde(default)]
    pub interval_blocks: Option<u64>,
    /// Snapshots kept in the index and offered to joiners.
    #[serde(default)]
    pub retain_count: Option<usize>,
    /// Cap on the blob bytes of the snapshots a node keeps.
    #[serde(default)]
    pub max_published_bytes: Option<u64>,
    /// Share of the data volume the kept snapshot blobs may take, percent.
    #[serde(default)]
    pub max_volume_pct: Option<u8>,
}

impl ProfileSnapshot {
    /// Applies the profile values to `policy`, leaving alone every key the
    /// node config set itself (`set_by_node` is asked with the key name:
    /// `interval_blocks`, `retain_count`, `max_published_bytes`,
    /// `max_volume_pct`).
    pub fn apply_to(
        &self,
        policy: &mut crate::snapshot::SnapshotConfig,
        set_by_node: &dyn Fn(&str) -> bool,
    ) {
        if let (Some(v), false) = (self.interval_blocks, set_by_node("interval_blocks")) {
            policy.interval_blocks = v;
        }
        if let (Some(v), false) = (self.retain_count, set_by_node("retain_count")) {
            policy.retain_count = v;
        }
        if let (Some(v), false) = (self.max_published_bytes, set_by_node("max_published_bytes")) {
            policy.max_published_bytes = v;
        }
        if let (Some(v), false) = (self.max_volume_pct, set_by_node("max_volume_pct")) {
            policy.max_volume_pct = v;
        }
    }
}

/// The `[onboarding]` table of a network profile: how hard the identity gate
/// acts on a node of this network unless the node config sets its own mode.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileOnboarding {
    /// `off`, `audit` or `enforce`.
    pub mode: GateMode,
}

impl NetworkProfile {
    /// Parses and checks a profile for `chain_id`.
    pub fn parse(source: &str, chain_id: u64) -> Result<Self> {
        let profile: Self = toml::from_str(source)
            .map_err(|e| NodeError::Config(format!("network profile: {e}")))?;
        if profile.version != PROFILE_VERSION {
            return Err(NodeError::Config(format!(
                "network profile is version {}, this node reads version {PROFILE_VERSION}",
                profile.version
            )));
        }
        if profile.chain_id != chain_id {
            return Err(NodeError::Config(format!(
                "network profile is for chain {}, this node runs chain {chain_id}",
                profile.chain_id
            )));
        }
        // Every entry must parse, so a typo is a start-up error and not a
        // network that silently stays at zero peers.
        profile.boot_identities()?;
        Ok(profile)
    }

    /// The boot identities the profile names: the relay's operator first,
    /// then the operators of the further relays, then each validator. A validator that names no relay of its own is
    /// reached through the profile's relay.
    pub fn boot_identities(&self) -> Result<Vec<BootIdentity>> {
        let mut entries = Vec::new();
        if let Some(relay) = &self.relay {
            entries.push(entry(&relay.operator_did, Some(&relay.url))?);
        }
        for relay in &self.relays {
            entries.push(entry(&relay.operator_did, Some(&relay.url))?);
        }
        let default_relay = self.relay.as_ref().map(|r| r.url.as_str());
        for v in &self.validators {
            entries.push(entry(&v.did, v.relay.as_deref().or(default_relay))?);
        }
        Ok(entries)
    }
}

fn entry(did: &str, relay: Option<&str>) -> Result<BootIdentity> {
    let raw = match relay {
        Some(url) => format!("{did}@{url}"),
        None => did.to_string(),
    };
    raw.parse()
        .map_err(|e| NodeError::Config(format!("network profile: {e}")))
}

/// Where a profile for `chain_id` is looked for, in order: the
/// `TENZRO_NETWORK_PROFILE` file, then `<dir of the running binary>/../share/
/// network/<chain_id>.toml` (the release layout: `bin/` beside `share/`).
pub fn search_paths(chain_id: u64, exe: Option<&Path>, env: Option<&str>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(explicit) = env.filter(|p| !p.trim().is_empty()) {
        paths.push(PathBuf::from(explicit));
    }
    if let Some(bin) = exe.and_then(Path::parent) {
        paths.push(
            bin.join("..")
                .join("share")
                .join("network")
                .join(format!("{chain_id}.toml")),
        );
    }
    paths
}

/// Reads the first profile that exists among `paths`. The explicit one (see
/// [`PROFILE_ENV`]) must exist; the release location may be absent.
pub fn load(
    chain_id: u64,
    paths: &[PathBuf],
    explicit: bool,
) -> Result<Option<(PathBuf, NetworkProfile)>> {
    for (i, path) in paths.iter().enumerate() {
        match std::fs::read_to_string(path) {
            Ok(source) => {
                let profile = NetworkProfile::parse(&source, chain_id)
                    .map_err(|e| NodeError::Config(format!("{}: {e}", path.display())))?;
                return Ok(Some((path.clone(), profile)));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if explicit && i == 0 {
                    return Err(NodeError::Config(format!(
                        "{PROFILE_ENV} names {}, which does not exist",
                        path.display()
                    )));
                }
            }
            Err(e) => {
                return Err(NodeError::Config(format!(
                    "network profile {}: {e}",
                    path.display()
                )));
            }
        }
    }
    Ok(None)
}

/// The identity gate mode the shipped profile for `chain_id` sets, when there
/// is a profile and it names one. A node whose config sets no
/// `onboarding.mode` of its own takes this value, so a release that ships the
/// profile enforces the identity rule without any setting by the operator.
pub fn onboarding_mode(
    chain_id: u64,
    exe: Option<&Path>,
    env: Option<&str>,
) -> Result<Option<GateMode>> {
    let explicit = env.is_some_and(|p| !p.trim().is_empty());
    let paths = search_paths(chain_id, exe, env);
    Ok(load(chain_id, &paths, explicit)?
        .and_then(|(_, profile)| profile.onboarding)
        .map(|o| o.mode))
}

/// The shipped profile for `chain_id`, when there is one. The explicit file
/// (see [`PROFILE_ENV`]) must exist; the release location may be absent.
pub fn shipped(
    chain_id: u64,
    exe: Option<&Path>,
    env: Option<&str>,
) -> Result<Option<NetworkProfile>> {
    let explicit = env.is_some_and(|p| !p.trim().is_empty());
    let paths = search_paths(chain_id, exe, env);
    Ok(load(chain_id, &paths, explicit)?.map(|(_, profile)| profile))
}

/// Adds the profile's boot identities to `boot` when the operator gave no
/// `--boot-nodes` (`flag_given` false). Entries already present (by identity)
/// are kept as they are. Returns how many were added.
///
/// The boot list the transport starts from is built from `boot` (see
/// [`crate::identity_bootstrap::boot_entries`]), so what is added here is what
/// the node dials.
pub fn apply(
    boot: &mut Vec<BootIdentity>,
    flag_given: bool,
    chain_id: u64,
    exe: Option<&Path>,
    env: Option<&str>,
) -> Result<usize> {
    if flag_given {
        return Ok(0);
    }
    let explicit = env.is_some_and(|p| !p.trim().is_empty());
    let paths = search_paths(chain_id, exe, env);
    let Some((path, profile)) = load(chain_id, &paths, explicit)? else {
        tracing::info!(
            chain_id,
            "no network profile shipped for this chain; joining through the genesis validators only"
        );
        return Ok(0);
    };
    let mut added = 0;
    for entry in profile.boot_identities()? {
        if !boot.iter().any(|b| b.did == entry.did) {
            boot.push(entry);
            added += 1;
        }
    }
    tracing::info!(profile = %path.display(), identities = added, "loaded the network profile");
    Ok(added)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAY_OP: &str =
        "did:tenzro:machine:1111111111111111111111111111111111111111111111111111111111111111";
    const V1: &str =
        "did:tenzro:machine:2222222222222222222222222222222222222222222222222222222222222222";
    const V2: &str =
        "did:tenzro:machine:3333333333333333333333333333333333333333333333333333333333333333";

    fn source(chain_id: u64) -> String {
        format!(
            r#"
version = 1
chain_id = {chain_id}
[relay]
url = "https://relay.example.net/"
operator_did = "{RELAY_OP}"
[[validators]]
did = "{V1}"
[[validators]]
did = "{V2}"
relay = "https://other.example.net/"
"#
        )
    }

    /// A release tree: `<root>/bin/tenzro-node` beside `<root>/share/network/`.
    fn release(chain_id: u64, body: &str) -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("bin")).unwrap();
        std::fs::create_dir_all(root.path().join("share/network")).unwrap();
        std::fs::write(
            root.path()
                .join("share/network")
                .join(format!("{chain_id}.toml")),
            body,
        )
        .unwrap();
        let exe = root.path().join("bin/tenzro-node");
        (root, exe)
    }

    #[test]
    fn a_node_with_no_boot_flag_and_no_env_joins_through_the_shipped_profile() {
        let (_root, exe) = release(13380, &source(13380));
        let mut boot = Vec::new();
        let added = apply(&mut boot, false, 13380, Some(&exe), None).unwrap();
        assert_eq!(added, 3);
        let dids: Vec<&str> = boot.iter().map(|b| b.did.as_str()).collect();
        assert_eq!(dids, [RELAY_OP, V1, V2]);
        // The relay operator and the validator without its own relay are
        // reached through the profile's relay; the other through its own.
        assert_eq!(
            boot[0].relay.as_ref().unwrap().as_str(),
            "https://relay.example.net/"
        );
        assert_eq!(
            boot[1].relay.as_ref().unwrap().as_str(),
            "https://relay.example.net/"
        );
        assert_eq!(
            boot[2].relay.as_ref().unwrap().as_str(),
            "https://other.example.net/"
        );
    }

    #[test]
    fn the_profile_reaches_the_boot_list_the_transport_starts_from() {
        let (_root, exe) = release(13380, &source(13380));
        let mut config = crate::config::NodeConfig::default();
        assert!(
            config.iroh.boot.is_empty(),
            "no flag, no env, nothing by hand"
        );
        apply(&mut config.iroh.boot, false, 13380, Some(&exe), None).unwrap();
        let entries = crate::identity_bootstrap::boot_entries(&config).unwrap();
        for did in [RELAY_OP, V1, V2] {
            assert!(entries.iter().any(|e| e.did == did), "{did} is dialled");
        }
        assert!(
            entries.iter().any(|e| e.relay.is_some()),
            "a relay is named"
        );
    }

    #[test]
    fn an_explicit_boot_flag_wins_and_the_profile_is_not_read() {
        let (_root, exe) = release(13380, "this is not toml");
        let mut boot = Vec::new();
        assert_eq!(apply(&mut boot, true, 13380, Some(&exe), None).unwrap(), 0);
        assert!(boot.is_empty());
    }

    #[test]
    fn operator_entries_are_kept_and_not_duplicated() {
        let (_root, exe) = release(13380, &source(13380));
        let mine: BootIdentity = V1.parse().unwrap();
        let mut boot = vec![mine.clone()];
        assert_eq!(apply(&mut boot, false, 13380, Some(&exe), None).unwrap(), 2);
        assert_eq!(boot.iter().filter(|b| b.did == V1).count(), 1);
        assert_eq!(boot[0], mine);
    }

    #[test]
    fn no_shipped_profile_is_not_an_error() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("bin")).unwrap();
        let exe = root.path().join("bin/tenzro-node");
        let mut boot = Vec::new();
        assert_eq!(apply(&mut boot, false, 13380, Some(&exe), None).unwrap(), 0);
    }

    #[test]
    fn a_profile_for_another_chain_or_a_bad_entry_refuses_to_start() {
        let (_root, exe) = release(13380, &source(99));
        assert!(apply(&mut Vec::new(), false, 13380, Some(&exe), None).is_err());
        let bad = source(13380).replace(V1, "/ip4/1.2.3.4/tcp/9000");
        let (_root, exe) = release(13380, &bad);
        assert!(apply(&mut Vec::new(), false, 13380, Some(&exe), None).is_err());
    }

    #[test]
    fn the_env_file_overrides_and_must_exist() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("mine.toml");
        std::fs::write(&file, source(7)).unwrap();
        let mut boot = Vec::new();
        let env = file.to_str().unwrap();
        assert_eq!(apply(&mut boot, false, 7, None, Some(env)).unwrap(), 3);
        let missing = dir.path().join("absent.toml");
        assert!(apply(&mut Vec::new(), false, 7, None, missing.to_str()).is_err());
    }

    #[test]
    fn a_profile_with_several_relays_names_every_operator_as_a_boot_identity() {
        let source = format!(
            "version = 1\nchain_id = 7\n[relay]\nurl = \"https://one.example.net/\"\noperator_did = \"{V1}\"\n\
             [[relays]]\nurl = \"https://two.example.net/\"\noperator_did = \"{V2}\"\n\
             [[validators]]\ndid = \"{V1}\"\n"
        );
        let profile = NetworkProfile::parse(&source, 7).unwrap();
        let boot = profile.boot_identities().unwrap();
        let urls: Vec<&str> = boot
            .iter()
            .filter_map(|b| b.relay.as_ref().map(|u| u.as_str()))
            .collect();
        assert_eq!(
            urls,
            [
                "https://one.example.net/",
                "https://two.example.net/",
                "https://one.example.net/"
            ]
        );
        assert_eq!(boot[1].did, V2);
    }

    /// The profile this repository ships for the testnet, read through the
    /// same parser the node uses at start-up.
    const SHIPPED_13380: &str = include_str!("../../../config/network/13380.toml");

    #[test]
    fn the_shipped_testnet_profile_parses_with_every_table() {
        let profile = NetworkProfile::parse(SHIPPED_13380, 13380)
            .expect("the shipped config/network/13380.toml must parse");
        assert_eq!(profile.chain_id, 13380);
        assert_eq!(profile.version, PROFILE_VERSION);
        assert_eq!(profile.validators.len(), 4);
        assert!(profile.relay.is_some());
        assert_eq!(
            profile.onboarding.expect("onboarding table").mode,
            GateMode::Enforce
        );
        let sync = profile.state_sync.as_ref().expect("state_sync table");
        assert!(sync.from.is_empty());
        let snap = profile.snapshot.as_ref().expect("snapshot table");
        assert_eq!(snap.interval_blocks, Some(10_000));
        assert_eq!(snap.retain_count, Some(2));
        assert_eq!(snap.max_published_bytes, Some(17_179_869_184));
        assert_eq!(snap.max_volume_pct, Some(15));
        // Every entry resolves to a boot identity: relay operator + 4 validators.
        assert_eq!(profile.boot_identities().unwrap().len(), 5);
    }

    #[test]
    fn profile_snapshot_values_apply_unless_the_node_config_set_them() {
        let profile = NetworkProfile::parse(SHIPPED_13380, 13380).unwrap();
        let snap = profile.snapshot.unwrap();
        let mut policy = crate::snapshot::SnapshotConfig::default();
        snap.apply_to(&mut policy, &|_| false);
        assert_eq!(policy.interval_blocks, 10_000);
        assert_eq!(policy.retain_count, 2);
        assert_eq!(policy.max_published_bytes, 17_179_869_184);
        assert_eq!(policy.max_volume_pct, 15);

        let mut policy = crate::snapshot::SnapshotConfig::default();
        let before = policy.interval_blocks;
        snap.apply_to(&mut policy, &|key| key == "interval_blocks");
        assert_eq!(policy.interval_blocks, before);
        assert_eq!(policy.max_published_bytes, 17_179_869_184);
    }

    #[test]
    fn unknown_keys_in_the_new_tables_are_refused() {
        let bad = format!("{}\n[snapshot]\nbogus = 1\n", source(13380));
        assert!(NetworkProfile::parse(&bad, 13380).is_err());
    }
}
