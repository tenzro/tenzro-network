//! What this machine knows about its own software updates, kept on disk where
//! `tenzro update`, `tenzro doctor` and the node all read it.
//!
//! Layout under the node's data directory:
//!
//! - `update/state.json`: [`UpdateRecord`], written by `tenzro update`.
//! - `update/restarting`: a marker a restart scheduler creates just before it
//!   restarts the node and the node removes at start-up. Nothing writes it in
//!   P0; [`current_state`] reads it so the advertised state already has a
//!   place for it.
//! - `upgrade/staged`: the binary an operator stages for a consensus upgrade
//!   (the same path the node's policy reflection reads).
//!
//! None of this is consensus state. A node that loses it only forgets what
//! the last `update check` saw.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The update state a node advertises to its peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateState {
    /// The running binary is the newest one on this machine.
    Running,
    /// A different binary is on this machine and the node is not running it yet.
    Staged,
    /// The node is about to restart onto another binary.
    Restarting,
}

impl UpdateState {
    /// The state as the lowercase word used in advertisements and status output.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Staged => "staged",
            Self::Restarting => "restarting",
        }
    }
}

/// What the last `tenzro update check` saw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastCheck {
    /// Unix milliseconds.
    pub checked_ms: u64,
    /// Release version the channel offered (semver).
    pub release: String,
    /// The manifest's monotonic number.
    pub manifest_version: u64,
}

/// `update/state.json`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct UpdateRecord {
    /// Highest manifest number ever verified and applied here. A manifest
    /// numbered at or below it is refused whatever its signature says.
    pub installed_manifest_version: u64,
    /// Highest timestamp number ever seen; an older one is a replay.
    pub highest_timestamp_version: u64,
    /// SHA-256 (hex) of the `tenzro-node` binary `tenzro update apply` last
    /// installed or restored: the digest a node running it advertises.
    pub installed_sha256: Option<String>,
    /// The most recent update check, if one has run.
    pub last_check: Option<LastCheck>,
}

/// The directory under the data directory that holds update state.
pub fn update_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("update")
}

/// The path of the update state file.
pub fn state_path(data_dir: &Path) -> PathBuf {
    update_dir(data_dir).join("state.json")
}

/// The marker file present while the node restarts onto a staged binary.
pub fn restarting_marker_path(data_dir: &Path) -> PathBuf {
    update_dir(data_dir).join("restarting")
}

/// The binary an operator stages for a consensus upgrade.
pub fn staged_binary_path(data_dir: &Path) -> PathBuf {
    data_dir.join("upgrade").join("staged")
}

/// Reads the record; a machine that never ran `tenzro update` has the default.
pub fn load(data_dir: &Path) -> std::io::Result<UpdateRecord> {
    match std::fs::read(state_path(data_dir)) {
        Ok(b) => serde_json::from_slice(&b).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{}: {e}", state_path(data_dir).display()),
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(UpdateRecord::default()),
        Err(e) => Err(e),
    }
}

/// Writes the record through a temporary file and a rename.
pub fn save(data_dir: &Path, rec: &UpdateRecord) -> std::io::Result<()> {
    let dir = update_dir(data_dir);
    std::fs::create_dir_all(&dir)?;
    let tmp = dir.join("state.json.tmp");
    std::fs::write(
        &tmp,
        serde_json::to_vec_pretty(rec).map_err(std::io::Error::other)?,
    )?;
    std::fs::rename(&tmp, state_path(data_dir))
}

/// Hex SHA-256 of a file, streamed.
pub fn file_sha256(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Whether the binary staged for a consensus upgrade differs from the running one.
pub fn staged_binary_differs(data_dir: &Path, running_sha256: &str) -> bool {
    match file_sha256(&staged_binary_path(data_dir)) {
        Ok(h) => h != running_sha256,
        Err(_) => false,
    }
}

/// The state to advertise, from what is on disk and the SHA-256 of the binary
/// this process is running.
pub fn current_state(data_dir: &Path, running_sha256: &str) -> UpdateState {
    if restarting_marker_path(data_dir).exists() {
        return UpdateState::Restarting;
    }
    let installed_differs = load(data_dir)
        .ok()
        .and_then(|r| r.installed_sha256)
        .is_some_and(|h| h != running_sha256);
    if installed_differs || staged_binary_differs(data_dir, running_sha256) {
        UpdateState::Staged
    } else {
        UpdateState::Running
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_machine_that_never_updated_is_running() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(load(d.path()).unwrap(), UpdateRecord::default());
        assert_eq!(current_state(d.path(), "aa"), UpdateState::Running);
    }

    #[test]
    fn an_installed_binary_the_process_is_not_running_is_staged() {
        let d = tempfile::tempdir().unwrap();
        let rec = UpdateRecord {
            installed_manifest_version: 3,
            highest_timestamp_version: 5,
            installed_sha256: Some("bb".into()),
            last_check: None,
        };
        save(d.path(), &rec).unwrap();
        assert_eq!(load(d.path()).unwrap(), rec);
        assert_eq!(current_state(d.path(), "aa"), UpdateState::Staged);
        assert_eq!(current_state(d.path(), "bb"), UpdateState::Running);
    }

    #[test]
    fn a_consensus_staged_binary_that_differs_is_staged_and_restarting_wins() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("upgrade")).unwrap();
        std::fs::write(staged_binary_path(d.path()), b"new").unwrap();
        let sha = file_sha256(&staged_binary_path(d.path())).unwrap();
        assert_eq!(current_state(d.path(), "aa"), UpdateState::Staged);
        assert_eq!(current_state(d.path(), &sha), UpdateState::Running);
        std::fs::create_dir_all(update_dir(d.path())).unwrap();
        std::fs::write(restarting_marker_path(d.path()), b"").unwrap();
        assert_eq!(current_state(d.path(), "aa"), UpdateState::Restarting);
    }

    #[test]
    fn a_damaged_state_file_is_an_error_not_a_blank_record() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(update_dir(d.path())).unwrap();
        std::fs::write(state_path(d.path()), b"{").unwrap();
        assert!(load(d.path()).is_err());
    }
}
