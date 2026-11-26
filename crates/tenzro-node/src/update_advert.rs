//! The software this node says it runs: its binary version, the SHA-256 of
//! the binary, and its update state. It goes into the signed endpoint record
//! (`tenzro_iroh::update_advert`) and into `tenzro_getNodeStatus`, which also
//! reports how the validators' stake divides over the versions their records
//! state ([`stake_by_version`]).
//!
//! Not consensus state. The update state comes from the files `tenzro update`
//! keeps (`tenzro_onboarding_types::update_state`).

use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tenzro_iroh::identity_transport::IdentityTransport;
use tenzro_iroh::update_advert::UpdateAdvert;
use tenzro_onboarding_types::update_state;

/// How often the update state is read again.
const REFRESH: Duration = Duration::from_secs(60);

/// The version of this binary.
pub const BINARY_VERSION: &str = env!("CARGO_PKG_VERSION");

/// SHA-256 of the executable this process started from, read once. Blocking:
/// it reads the whole file.
pub fn running_digest() -> Option<&'static str> {
    static DIGEST: OnceLock<Option<String>> = OnceLock::new();
    DIGEST
        .get_or_init(|| {
            // /proc/self/exe still opens the running image after the file was replaced.
            let path = if cfg!(target_os = "linux") { Some("/proc/self/exe".into()) } else { std::env::current_exe().ok() };
            match update_state::file_sha256(&path?) {
                Ok(h) => Some(h),
                Err(e) => {
                    tracing::warn!(error = %e, "could not hash the running binary; no software advert");
                    None
                }
            }
        })
        .as_deref()
}

/// The advert for a node running the binary with SHA-256 `digest`.
pub fn advert(data_dir: &Path, digest: &str) -> UpdateAdvert {
    UpdateAdvert {
        binary_version: BINARY_VERSION.to_string(),
        platform_digest: digest.to_string(),
        state: update_state::current_state(data_dir, digest),
    }
}

/// The `update` object of `tenzro_getNodeStatus`.
pub async fn status_json(data_dir: std::path::PathBuf) -> serde_json::Value {
    let digest = tokio::task::spawn_blocking(running_digest)
        .await
        .ok()
        .flatten();
    match digest {
        Some(d) => {
            let a = advert(&data_dir, d);
            serde_json::json!({
                "binary_version": a.binary_version,
                "platform_digest": a.platform_digest,
                "state": a.state.as_str(),
            })
        }
        None => {
            serde_json::json!({ "binary_version": BINARY_VERSION, "platform_digest": null, "state": null })
        }
    }
}

/// How bonded validator stake divides over the binary versions the
/// validators' machines state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VersionStake {
    /// Stake of every validator counted.
    pub total: u128,
    /// Per version: the version, how many validators state it and their
    /// stake. Most stake first, then by version.
    pub versions: Vec<(String, usize, u128)>,
    /// Validators whose machine states no version this node could verify,
    /// and their stake.
    pub unreported: (usize, u128),
}

impl VersionStake {
    fn bps(&self, stake: u128) -> u64 {
        if self.total == 0 {
            return 0;
        }
        u64::try_from(stake.saturating_mul(10_000) / self.total).unwrap_or(10_000)
    }

    /// The `network` object of the status's `update`.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "total_stake": self.total.to_string(),
            "versions": self.versions.iter().map(|(version, validators, stake)| serde_json::json!({
                "binary_version": version,
                "validators": validators,
                "stake": stake.to_string(),
                "stake_bps": self.bps(*stake),
            })).collect::<Vec<_>>(),
            "unreported": {
                "validators": self.unreported.0,
                "stake": self.unreported.1.to_string(),
                "stake_bps": self.bps(self.unreported.1),
            },
        })
    }
}

/// Divide the stake of `validators` (machine identity, when the validator
/// names one, and stake) over the versions `version_of` reads for their
/// machines. A validator with no machine identity, or whose machine states
/// no version, counts as unreported.
pub fn stake_by_version(
    validators: &[(Option<String>, u128)],
    version_of: impl Fn(&str) -> Option<String>,
) -> VersionStake {
    let mut by_version: std::collections::BTreeMap<String, (usize, u128)> = Default::default();
    let mut out = VersionStake::default();
    for (did, stake) in validators {
        out.total = out.total.saturating_add(*stake);
        match did.as_deref().and_then(&version_of) {
            Some(version) => {
                let entry = by_version.entry(version).or_default();
                entry.0 += 1;
                entry.1 = entry.1.saturating_add(*stake);
            }
            None => {
                out.unreported.0 += 1;
                out.unreported.1 = out.unreported.1.saturating_add(*stake);
            }
        }
    }
    out.versions = by_version
        .into_iter()
        .map(|(version, (n, stake))| (version, n, stake))
        .collect();
    out.versions
        .sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
    out
}

/// [`stake_by_version`] for the current validator set of `node`: each
/// validator's version is the one its machine's verified endpoint record
/// states, and this node's own is the version of this binary. `None` while
/// the node has no consensus or no identity transport.
pub fn network_stake(node: &crate::node::TenzroNode) -> Option<VersionStake> {
    let consensus = node.consensus()?;
    let store = node.identity_transport.as_ref()?.store().clone();
    let state = crate::rpc::chain_state_of(node);
    let set = consensus.epoch_manager().current_validator_set();
    let validators: Vec<(Option<String>, u128)> = set
        .active_validators()
        .iter()
        .map(|v| {
            let machine = crate::identity_bootstrap::validator_machine(v, |address| {
                let state = state.as_ref()?;
                tenzro_vm::native::validator_machine::machine_of(state, address.as_bytes())
                    .map(|m| (m.did(), m.tagged_ml_dsa()))
            });
            (machine.map(|(did, _)| did), v.stake)
        })
        .collect();
    let own = crate::identity_bootstrap::machine_did();
    Some(stake_by_version(&validators, |did| {
        if own.as_deref() == Some(did) {
            return Some(BINARY_VERSION.to_string());
        }
        let record = store.lookup(did)?;
        record
            .verified_update()
            .ok()
            .flatten()
            .map(|a| a.binary_version.clone())
    }))
}

/// Keeps this node's record stating the software it runs. The first state is
/// declared as soon as the binary is hashed, then re-read every minute: a
/// record is re-signed only when the advert changed.
pub fn keep(transport: &Arc<IdentityTransport>, data_dir: std::path::PathBuf) {
    let transport = transport.clone();
    tokio::spawn(async move {
        let Some(digest) = tokio::task::spawn_blocking(running_digest)
            .await
            .ok()
            .flatten()
        else {
            return;
        };
        loop {
            let dir = data_dir.clone();
            if let Ok(a) = tokio::task::spawn_blocking(move || advert(&dir, digest)).await {
                transport.declare_update(a);
            }
            tokio::time::sleep(REFRESH).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_onboarding_types::update_state::UpdateState;

    /// A release notice names a release as `major.minor.patch`; the node
    /// compares its own version with it, so the two must be one format and
    /// this binary must state the release it is built for.
    #[test]
    fn the_binary_version_is_the_release_in_the_notice_format() {
        let v: tenzro_update_notice::notice::Version = BINARY_VERSION.parse().unwrap();
        assert_eq!(v.to_string(), BINARY_VERSION);
        assert_eq!(BINARY_VERSION, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn the_advert_names_this_binary_and_its_state() {
        let d = tempfile::tempdir().unwrap();
        let a = advert(d.path(), &"cd".repeat(32));
        assert_eq!(a.binary_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(a.state, UpdateState::Running);
        std::fs::create_dir_all(d.path().join("upgrade")).unwrap();
        std::fs::write(update_state::staged_binary_path(d.path()), b"another build").unwrap();
        assert_eq!(
            advert(d.path(), &"cd".repeat(32)).state,
            UpdateState::Staged
        );
    }

    #[test]
    fn stake_divides_over_the_versions_the_validators_machines_state() {
        let validators = vec![
            (Some("did:a".to_string()), 50u128),
            (Some("did:b".to_string()), 30),
            (Some("did:c".to_string()), 15),
            // A machine that states nothing, and a validator naming no machine.
            (Some("did:d".to_string()), 4),
            (None, 1),
        ];
        let s = stake_by_version(&validators, |did| match did {
            "did:a" | "did:c" => Some("0.2.2".to_string()),
            "did:b" => Some("0.2.1".to_string()),
            _ => None,
        });
        assert_eq!(s.total, 100);
        assert_eq!(
            s.versions,
            vec![("0.2.2".to_string(), 2, 65), ("0.2.1".to_string(), 1, 30)]
        );
        assert_eq!(s.unreported, (2, 5));
        let json = s.to_json();
        assert_eq!(json["versions"][0]["stake_bps"], 6_500);
        assert_eq!(json["versions"][1]["stake_bps"], 3_000);
        assert_eq!(json["unreported"]["stake_bps"], 500);
        assert_eq!(json["total_stake"], "100");
        // No validators: no shares, and no division by zero.
        assert_eq!(
            stake_by_version(&[], |_| None).to_json()["unreported"]["stake_bps"],
            0
        );
    }

    #[test]
    fn the_running_binary_hashes_to_a_digest_an_advert_accepts() {
        let d = running_digest().expect("the test binary can be read");
        assert_eq!(d.len(), 64);
    }
}
