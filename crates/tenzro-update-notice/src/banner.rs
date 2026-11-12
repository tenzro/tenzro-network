//! The one-line message a person sees, and when they do not.
//!
//! One line, never a prompt, never a wait: nothing here reads the network.
//! A surface (a command after it ran, `status`, `doctor`, the console header)
//! asks [`banner`] with what it knows and prints the line if there is one.
//!
//! The line is shown once per release per UTC day, tracked in
//! `<data_dir>/update/notice-shown.json`. It is hidden when the output is not
//! a terminal, with `--quiet`, in JSON output (which carries
//! [`json_fields`] instead), and when the owner turned notices off
//! ([`Prefs`]).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::notice::{Notice, Severity, Version};

const DAY_MS: u64 = 24 * 3600 * 1000;

/// A restart within this many blocks of the epoch's end is not advised.
pub const SAFE_MARGIN_BLOCKS: u64 = 50;

/// The owner's choices about notices, `<data_dir>/update/notice-prefs.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prefs {
    /// Whether to show notices. On by default.
    #[serde(default = "yes")]
    pub notices: bool,
}

fn yes() -> bool {
    true
}

impl Default for Prefs {
    fn default() -> Self {
        Self { notices: true }
    }
}

fn prefs_path(data_dir: &Path) -> PathBuf {
    data_dir.join("update").join("notice-prefs.json")
}

impl Prefs {
    /// The saved choices; a missing or unreadable file is the defaults.
    pub fn load(data_dir: &Path) -> Self {
        std::fs::read(prefs_path(data_dir))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Saves the choices.
    pub fn save(&self, data_dir: &Path) -> std::io::Result<()> {
        let path = prefs_path(data_dir);
        std::fs::create_dir_all(path.parent().expect("the prefs path has a parent"))?;
        std::fs::write(
            path,
            serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?,
        )
    }

    /// Whether notices show, counting `TENZRO_UPDATE_NOTICES` (`off`, `0`, `false` or `no` turns them off).
    pub fn notices_shown(&self, env: Option<&str>) -> bool {
        let off = env.is_some_and(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "off" | "0" | "false" | "no"
            )
        });
        self.notices && !off
    }
}

/// Where the output goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Surface {
    /// Standard output and error are a terminal.
    pub is_terminal: bool,
    /// `--quiet` was given.
    pub quiet: bool,
    /// JSON output was asked for.
    pub json: bool,
}

/// Where the chain is in its epoch, from the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochView {
    /// The current epoch number.
    pub epoch: u64,
    /// Blocks until this epoch ends, when the node knows.
    pub blocks_to_boundary: Option<u64>,
}

/// The line for `notice` as seen from `running`, or `None` when the notice
/// offers nothing newer. A security release gets a stronger line and a
/// required-by-epoch release a countdown.
pub fn line(notice: &Notice, running: Version, epoch: Option<EpochView>) -> Option<String> {
    line_for_os(notice, running, epoch, std::env::consts::OS)
}

/// What an operator is told to do to take a release: run `tenzro update`
/// (introduced by `lead`, e.g. "Run"), or on Windows, where the running
/// program cannot be replaced, install the release with its MSI.
pub fn install_hint(os: &str, lead: &str) -> String {
    if os == "windows" {
        "Install the new release with its MSI".to_string()
    } else {
        format!("{lead}: tenzro update")
    }
}

/// [`line`] for the operating system named `os` (`std::env::consts::OS`).
pub fn line_for_os(
    notice: &Notice,
    running: Version,
    epoch: Option<EpochView>,
    os: &str,
) -> Option<String> {
    let latest = notice.release();
    if latest <= running {
        return None;
    }
    let hint = |lead: &str| install_hint(os, lead);
    Some(match notice.severity {
        Severity::Normal => format!(
            "Tenzro {latest} is available (you run {running}). {}",
            hint("Run")
        ),
        Severity::Security => {
            format!(
                "Security update: Tenzro {latest} fixes a security issue (you run {running}). {}",
                hint("Install it now")
            )
        }
        Severity::RequiredByEpoch { epoch: due } => match epoch {
            Some(e) if e.epoch >= due => format!(
                "Tenzro {latest} has been required since epoch {due} (now epoch {}; you run {running}). {}",
                e.epoch,
                hint("Update now")
            ),
            Some(e) => {
                let left = due - e.epoch;
                format!(
                    "Tenzro {latest} is required from epoch {due}: {left} epoch{} left (now epoch {}; you run {running}). {}",
                    if left == 1 { "" } else { "s" },
                    e.epoch,
                    hint("Run")
                )
            }
            None => format!(
                "Tenzro {latest} is required from epoch {due} (you run {running}). {}",
                hint("Run")
            ),
        },
    })
}

/// Whether a validator or provider can restart onto the new binary now, and a
/// line saying so. Never at an epoch boundary: within [`SAFE_MARGIN_BLOCKS`]
/// of the end of the epoch the advice is to wait.
pub fn restart_advice(view: Option<EpochView>) -> (bool, String) {
    match view.and_then(|v| v.blocks_to_boundary.map(|b| (v.epoch, b))) {
        Some((epoch, b)) if b <= SAFE_MARGIN_BLOCKS => {
            (false, format!("Wait before restarting: epoch {epoch} ends in {b} blocks. A validator restart takes about 1.5 minutes."))
        }
        Some((epoch, b)) => (true, format!("Safe to restart now: epoch {epoch} ends in {b} blocks.")),
        None => (false, "The epoch position is unknown; restart only when the node reports it is not at an epoch boundary.".into()),
    }
}

fn shown_path(data_dir: &Path) -> PathBuf {
    data_dir.join("update").join("notice-shown.json")
}

#[derive(Serialize, Deserialize)]
struct Shown {
    version: String,
    day: u64,
}

fn already_shown(data_dir: &Path, version: Version, now_ms: u64) -> bool {
    std::fs::read(shown_path(data_dir))
        .ok()
        .and_then(|b| serde_json::from_slice::<Shown>(&b).ok())
        .is_some_and(|s| s.version == version.to_string() && s.day == now_ms / DAY_MS)
}

fn record_shown(data_dir: &Path, version: Version, now_ms: u64) {
    let path = shown_path(data_dir);
    let body = serde_json::to_vec(&Shown {
        version: version.to_string(),
        day: now_ms / DAY_MS,
    })
    .unwrap_or_default();
    if let Some(dir) = path.parent()
        && std::fs::create_dir_all(dir).is_ok()
    {
        let _ = std::fs::write(path, body);
    }
}

/// The banner to print, if the rules allow one now, and records that it was
/// shown. `None` for a hidden surface, a notice that offers nothing newer, or a
/// release already shown today. A failure to record is not an error: the line
/// may then show again, which is better than a failed command.
pub fn banner(
    data_dir: &Path,
    notice: &Notice,
    running: Version,
    epoch: Option<EpochView>,
    surface: Surface,
    prefs_env: Option<&str>,
    now_ms: u64,
) -> Option<String> {
    if !surface.is_terminal
        || surface.quiet
        || surface.json
        || !Prefs::load(data_dir).notices_shown(prefs_env)
    {
        return None;
    }
    let text = line(notice, running, epoch)?;
    let latest = notice.release();
    if already_shown(data_dir, latest, now_ms) {
        return None;
    }
    record_shown(data_dir, latest, now_ms);
    Some(text)
}

/// The fields JSON output carries instead of the banner.
pub fn json_fields(notice: Option<&Notice>, running: Version) -> serde_json::Value {
    match notice.filter(|n| n.release() > running) {
        Some(n) => serde_json::json!({
            "update_available": true,
            "latest_version": n.version,
            "severity": n.severity.as_str(),
            "required_by_epoch": match n.severity { Severity::RequiredByEpoch { epoch } => Some(epoch), _ => None },
            "notes_url": n.notes_url,
        }),
        None => serde_json::json!({
            "update_available": false,
            "latest_version": serde_json::Value::Null,
            "severity": serde_json::Value::Null,
            "required_by_epoch": serde_json::Value::Null,
            "notes_url": serde_json::Value::Null,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notice::fixture::*;

    const TTY: Surface = Surface {
        is_terminal: true,
        quiet: false,
        json: false,
    };
    const NOTICE_NOW: u64 = NOW;

    fn running() -> Version {
        "0.2.1".parse().unwrap()
    }

    fn show(d: &Path, n: &Notice, surface: Surface, now: u64) -> Option<String> {
        banner(d, n, running(), None, surface, None, now)
    }

    #[test]
    fn the_normal_line_names_both_versions_and_the_command() {
        let n = notice("0.2.2", Severity::Normal);
        assert_eq!(
            line_for_os(&n, running(), None, "linux").unwrap(),
            "Tenzro 0.2.2 is available (you run 0.2.1). Run: tenzro update"
        );
        assert!(
            line_for_os(&notice("0.2.1", Severity::Normal), running(), None, "linux").is_none()
        );
        assert!(
            line_for_os(&notice("0.2.0", Severity::Normal), running(), None, "linux").is_none()
        );
    }

    #[test]
    fn a_security_release_gets_a_stronger_line() {
        let l = line_for_os(
            &notice("0.2.2", Severity::Security),
            running(),
            None,
            "linux",
        )
        .unwrap();
        assert!(
            l.starts_with("Security update:") && l.contains("0.2.2") && l.contains("tenzro update"),
            "{l}"
        );
    }

    #[test]
    fn a_required_by_epoch_release_counts_down() {
        let n = notice("0.2.2", Severity::RequiredByEpoch { epoch: 40 });
        let at = |e| {
            line_for_os(
                &n,
                running(),
                Some(EpochView {
                    epoch: e,
                    blocks_to_boundary: None,
                }),
                "linux",
            )
            .unwrap()
        };
        assert!(
            at(37).contains("3 epochs left") && at(37).contains("epoch 40"),
            "{}",
            at(37)
        );
        assert!(at(39).contains("1 epoch left"), "{}", at(39));
        assert!(at(40).contains("required since epoch 40"), "{}", at(40));
        assert!(at(45).contains("required since epoch 40") && at(45).contains("now epoch 45"));
        assert!(
            line_for_os(&n, running(), None, "linux")
                .unwrap()
                .contains("required from epoch 40")
        );
    }

    #[test]
    fn the_line_shows_once_per_version_per_day() {
        let d = tempfile::tempdir().unwrap();
        let n = notice("0.2.2", Severity::Normal);
        assert!(show(d.path(), &n, TTY, NOTICE_NOW).is_some());
        assert!(
            show(d.path(), &n, TTY, NOTICE_NOW + 1000).is_none(),
            "the same day"
        );
        assert!(
            show(d.path(), &n, TTY, NOTICE_NOW + DAY_MS).is_some(),
            "the next day"
        );
        // A newer release shows at once, the same day.
        let newer = notice("0.2.3", Severity::Normal);
        assert!(show(d.path(), &newer, TTY, NOTICE_NOW + DAY_MS + 5).is_some());
    }

    #[test]
    fn hidden_surfaces_neither_print_nor_use_up_the_day() {
        let d = tempfile::tempdir().unwrap();
        let n = notice("0.2.2", Severity::Normal);
        for s in [
            Surface {
                is_terminal: false,
                ..TTY
            },
            Surface { quiet: true, ..TTY },
            Surface { json: true, ..TTY },
        ] {
            assert!(show(d.path(), &n, s, NOTICE_NOW).is_none());
        }
        assert!(
            show(d.path(), &n, TTY, NOTICE_NOW).is_some(),
            "still unseen after the hidden calls"
        );
    }

    #[test]
    fn notices_turned_off_are_hidden_by_file_and_by_environment() {
        let d = tempfile::tempdir().unwrap();
        let n = notice("0.2.2", Severity::Normal);
        assert!(banner(d.path(), &n, running(), None, TTY, Some("off"), NOTICE_NOW).is_none());
        Prefs { notices: false }.save(d.path()).unwrap();
        assert!(show(d.path(), &n, TTY, NOTICE_NOW).is_none());
        Prefs::default().save(d.path()).unwrap();
        assert!(show(d.path(), &n, TTY, NOTICE_NOW).is_some());
    }

    #[test]
    fn json_carries_fields_not_the_line() {
        let n = notice("0.2.2", Severity::RequiredByEpoch { epoch: 40 });
        let j = json_fields(Some(&n), running());
        assert_eq!(j["update_available"], true);
        assert_eq!(j["latest_version"], "0.2.2");
        assert_eq!(j["severity"], "required_by_epoch");
        assert_eq!(j["required_by_epoch"], 40);
        assert_eq!(j["notes_url"], "https://tenzro.com/releases/notes");
        let none = json_fields(None, running());
        assert_eq!(none["update_available"], false);
        assert!(none["latest_version"].is_null());
        assert_eq!(
            json_fields(Some(&notice("0.2.1", Severity::Normal)), running())["update_available"],
            false
        );
    }

    #[test]
    fn a_restart_is_not_advised_at_an_epoch_boundary() {
        let (safe, line) = restart_advice(Some(EpochView {
            epoch: 37,
            blocks_to_boundary: Some(12),
        }));
        assert!(!safe && line.contains("Wait"), "{line}");
        let (safe, line) = restart_advice(Some(EpochView {
            epoch: 37,
            blocks_to_boundary: Some(400),
        }));
        assert!(safe && line.contains("Safe to restart"), "{line}");
        assert!(!restart_advice(None).0);
    }

    #[test]
    fn on_windows_the_line_points_at_the_msi_and_never_at_the_command() {
        for severity in [
            Severity::Normal,
            Severity::Security,
            Severity::RequiredByEpoch { epoch: 9 },
        ] {
            let n = notice("0.2.2", severity);
            for epoch in [
                None,
                Some(EpochView {
                    epoch: 5,
                    blocks_to_boundary: None,
                }),
                Some(EpochView {
                    epoch: 9,
                    blocks_to_boundary: None,
                }),
            ] {
                let l = line_for_os(&n, running(), epoch, "windows").unwrap();
                assert!(l.ends_with("Install the new release with its MSI"), "{l}");
                assert!(!l.contains("tenzro update"), "{l}");
            }
        }
        assert_eq!(install_hint("linux", "Run"), "Run: tenzro update");
        assert_eq!(
            install_hint("macos", "Update now"),
            "Update now: tenzro update"
        );
    }
}
