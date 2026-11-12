//! Release notices in the CLI: reading the cached notice, refreshing it, the
//! banner, and `tenzro update notice` / `tenzro update notices`.
//!
//! A notice is data. Nothing here downloads a release or changes the
//! installed binaries; `tenzro update` stays the only way in.
//!
//! Where a notice comes from, in order: the cache the node and earlier checks
//! keep (`<data-dir>/update/notice.json`); the release channel's
//! `notice.json`; and, when the channel cannot be reached, any node's
//! `tenzro_getUpdateNotice` method. All three are verified against the release
//! key before they are kept, so a node that relays one is not trusted.

use std::io::IsTerminal as _;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use tenzro_update_notice::banner::{self, EpochView, Prefs, Surface};
use tenzro_update_notice::notice::{self, Notice, Policy, Version};
use tenzro_update_notice::{NoticeStore, Offer};

use super::{Channel, now_ms};
use crate::output;

/// The notice channel name this install follows (`stable` unless `TENZRO_RELEASE_CHANNEL` says otherwise).
pub fn channel_name() -> String {
    std::env::var("TENZRO_RELEASE_CHANNEL").unwrap_or_else(|_| "stable".to_string())
}

/// The data directory this install keeps update state in: `TENZRO_DATA_DIR`, else the default.
pub fn data_dir() -> std::path::PathBuf {
    std::env::var_os("TENZRO_DATA_DIR")
        .map(Into::into)
        .unwrap_or_else(tenzro_types::paths::default_data_dir)
}

fn running() -> Version {
    env!("CARGO_PKG_VERSION")
        .parse()
        .expect("the package version is major.minor.patch")
}

fn keys(data_dir: &Path) -> Vec<Vec<u8>> {
    notice::trusted_keys(data_dir).unwrap_or_else(|_| vec![notice::release_key_sec1()])
}

/// Runs `f` with the policy this install applies to notices.
fn with_policy<T>(data_dir: &Path, now: u64, f: impl FnOnce(&Policy<'_>) -> T) -> T {
    let keys = keys(data_dir);
    let channel = channel_name();
    f(&Policy {
        keys: &keys,
        channel: &channel,
        running: running(),
        now_ms: now,
    })
}

/// The cached notice, if it still verifies. Reads the disk only.
pub fn cached(data_dir: &Path, now: u64) -> Option<Notice> {
    with_policy(data_dir, now, |p| {
        NoticeStore::open(data_dir).cached(p).map(|(n, _)| n)
    })
}

/// The read function for the assistant, the Hub and scripts: what the cached
/// notice says, as one JSON object (see [`NoticeStore::status`]). Reads the
/// disk only and never installs anything.
pub fn read_status(data_dir: &Path, now: u64) -> serde_json::Value {
    with_policy(data_dir, now, |p| NoticeStore::open(data_dir).status(p))
}

fn offer(data_dir: &Path, bytes: &[u8], now: u64) -> Result<Offer> {
    with_policy(data_dir, now, |p| {
        NoticeStore::open(data_dir).offer(bytes, p)
    })
    .map_err(|e| anyhow!("{e}"))
}

/// What a node's `tenzro_getUpdateNotice` said.
pub struct FromNode {
    /// The notice, after it verified and was kept.
    pub notice: Option<Notice>,
    /// Where the node is in its epoch.
    pub epoch: Option<EpochView>,
}

/// Asks the node at `rpc_url` for its notice. The notice is verified and kept
/// as if it came from the channel; a bad one is ignored.
pub async fn from_node(data_dir: &Path, rpc_url: &str, now: u64) -> FromNode {
    let client = crate::rpc::RpcClient::new(rpc_url);
    let call = client.call::<serde_json::Value>("tenzro_getUpdateNotice", serde_json::json!([]));
    let reply = match tokio::time::timeout(Duration::from_secs(3), call).await {
        Ok(Ok(v)) => v,
        _ => {
            return FromNode {
                notice: cached(data_dir, now),
                epoch: None,
            };
        }
    };
    let epoch = reply
        .get("epoch")
        .and_then(|e| serde_json::from_value::<EpochView>(e.clone()).ok());
    if let Some(env) = reply.get("notice").filter(|v| v.is_object())
        && let Ok(bytes) = serde_json::to_vec(env)
    {
        let _ = offer(data_dir, &bytes, now);
    }
    FromNode {
        notice: cached(data_dir, now),
        epoch,
    }
}

/// Fetches the channel's `notice.json`, then, if that fails, asks the node at
/// `rpc_url`. Returns the newest notice held afterwards and says where the
/// last attempt came from.
pub async fn refresh(
    data_dir: &Path,
    channel_url: &str,
    rpc_url: Option<&str>,
    now: u64,
) -> (Option<Notice>, Result<&'static str>) {
    let channel = Channel::parse(channel_url);
    let from_channel = async {
        let bytes = channel
            .small("notice.json", notice::MAX_ENVELOPE_BYTES)
            .await?;
        offer(data_dir, &bytes, now)?;
        anyhow::Ok(())
    };
    let channel_err = match tokio::time::timeout(Duration::from_secs(8), from_channel).await {
        Ok(Ok(())) => return (cached(data_dir, now), Ok("the release channel")),
        Ok(Err(e)) => e,
        Err(_) => anyhow!("the release channel did not answer in time"),
    };
    if let Some(url) = rpc_url {
        let got = from_node(data_dir, url, now).await;
        if got.notice.is_some() {
            return (got.notice, Ok("a node"));
        }
    }
    (cached(data_dir, now), Err(channel_err))
}

/// Where this output goes.
pub fn surface(quiet: bool, json: bool) -> Surface {
    Surface {
        is_terminal: std::io::stdout().is_terminal() && std::io::stderr().is_terminal(),
        quiet,
        json,
    }
}

fn env_pref() -> Option<String> {
    std::env::var("TENZRO_UPDATE_NOTICES").ok()
}

/// The banner line for the cached notice, if the rules allow one now. Reads
/// the disk only, so it never delays a command.
pub fn banner_line(
    data_dir: &Path,
    epoch: Option<EpochView>,
    surface: Surface,
    now: u64,
) -> Option<String> {
    let n = cached(data_dir, now)?;
    banner::banner(
        data_dir,
        &n,
        running(),
        epoch,
        surface,
        env_pref().as_deref(),
        now,
    )
}

/// Prints the banner to standard error, after a command ran.
pub fn print_after_command(data_dir: &Path, quiet: bool, json: bool) {
    if let Some(line) = banner_line(data_dir, None, surface(quiet, json), now_ms()) {
        eprintln!("{line}");
    }
}

/// The short form of the banner for the full-screen console's header, under
/// the same once-per-day rule. The console is a terminal and prints no JSON.
pub fn console_line(data_dir: &Path) -> Option<String> {
    let n = cached(data_dir, now_ms())?;
    let s = Surface {
        is_terminal: true,
        quiet: false,
        json: false,
    };
    banner::banner(
        data_dir,
        &n,
        running(),
        None,
        s,
        env_pref().as_deref(),
        now_ms(),
    )?;
    let how = banner::install_hint(std::env::consts::OS, "");
    let how = how.strip_prefix(": ").unwrap_or(&how);
    Some(match n.severity {
        notice::Severity::Normal => format!("update {} available: {how}", n.version),
        notice::Severity::Security => format!("security update {}: {how}", n.version),
        notice::Severity::RequiredByEpoch { epoch } => {
            format!("update {} required from epoch {epoch}: {how}", n.version)
        }
    })
}

/// Whether any of `roles` is one whose restart its operator times: a
/// validator or a provider.
pub fn serves_role<'a>(roles: impl IntoIterator<Item = &'a str>) -> bool {
    roles
        .into_iter()
        .any(|r| matches!(r, "validator" | "provider" | "model-provider" | "ai"))
}

/// The restart advice for the operator of a node that serves a role, from
/// where the node at `rpc_url` says it is in its epoch.
pub async fn restart_advice(data_dir: &Path, rpc_url: &str, now: u64) -> String {
    banner::restart_advice(from_node(data_dir, rpc_url, now).await.epoch).1
}

/// The restart advice a validator or provider gets with the banner: only when
/// a newer release exists and this machine serves a role.
pub fn restart_line(
    notice: Option<&Notice>,
    serves_role: bool,
    epoch: Option<EpochView>,
) -> Option<String> {
    let n = notice?;
    if !serves_role || n.release() <= running() {
        return None;
    }
    Some(banner::restart_advice(epoch).1)
}

/// What `status` shows about releases.
pub struct StatusUpdate {
    /// The newest verified notice, if any.
    pub notice: Option<Notice>,
    /// Where the node is in its epoch.
    pub epoch: Option<EpochView>,
    /// Whether this machine serves a validator or provider role.
    pub serves_role: bool,
}

/// Asks the node at `rpc_url` (and the cache) what release news there is.
pub async fn for_status(
    data_dir: &Path,
    rpc_url: &str,
    serves_role: bool,
    now: u64,
) -> StatusUpdate {
    let got = from_node(data_dir, rpc_url, now).await;
    StatusUpdate {
        notice: got.notice,
        epoch: got.epoch,
        serves_role,
    }
}

impl StatusUpdate {
    /// The fields JSON output carries: `update_available`, `latest_version`,
    /// `severity`, `notes_url`, and for a machine with a role, when a restart is safe.
    pub fn json(&self) -> serde_json::Value {
        let mut j = banner::json_fields(self.notice.as_ref(), running());
        if let Some(line) = restart_line(self.notice.as_ref(), self.serves_role, self.epoch) {
            let (safe, _) = banner::restart_advice(self.epoch);
            j["restart_safe"] = safe.into();
            j["restart_advice"] = line.into();
        }
        j
    }

    /// The lines to print under the readout: the banner (once per version per
    /// day) and, for a validator or provider with an update pending, the
    /// restart advice. Empty on a hidden surface.
    pub fn lines(&self, data_dir: &Path, surface: Surface, now: u64) -> Vec<String> {
        let mut out = Vec::new();
        let Some(n) = &self.notice else {
            return out;
        };
        if !surface.is_terminal
            || surface.quiet
            || surface.json
            || !Prefs::load(data_dir).notices_shown(env_pref().as_deref())
        {
            return out;
        }
        out.extend(banner::banner(
            data_dir,
            n,
            running(),
            self.epoch,
            surface,
            env_pref().as_deref(),
            now,
        ));
        out.extend(restart_line(Some(n), self.serves_role, self.epoch));
        out
    }
}

/// `tenzro update notice`
#[derive(Debug, Parser)]
pub struct NoticeCmd {
    /// Ask the release channel (and, failing that, a node) for a newer notice first.
    #[arg(long)]
    refresh: bool,
    /// The release channel to ask: an https URL or a local directory.
    #[arg(long, env = "TENZRO_UPDATE_CHANNEL", default_value = super::DEFAULT_CHANNEL)]
    channel: String,
    /// Print the notice as one JSON object.
    #[arg(long)]
    json: bool,
    #[command(flatten)]
    at: super::Where,
}

impl NoticeCmd {
    pub(super) async fn execute(&self) -> Result<()> {
        let data_dir = self.at.data_dir();
        if self.refresh {
            let (endpoint, _) = crate::endpoint::resolve();
            let (_, how) = refresh(&data_dir, &self.channel, Some(&endpoint), now_ms()).await;
            if let Err(e) = how {
                output::print_warning(&format!("no newer notice could be fetched: {e:#}"));
            }
        }
        if self.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&read_status(&data_dir, now_ms()))?
            );
            return Ok(());
        }
        match cached(&data_dir, now_ms()) {
            None => output::print_info(
                "No release notice is held. `tenzro update notice --refresh` asks the channel.",
            ),
            Some(n) if n.release() <= running() => output::print_success(&format!(
                "tenzro {} is current: the newest notice names {}",
                running(),
                n.version
            )),
            Some(n) => {
                output::print_info(&banner::line(&n, running(), None).unwrap_or_default());
                output::print_field("Severity", n.severity.as_str());
                output::print_field("Notes", &n.notes);
                if !n.notes_url.is_empty() {
                    output::print_field("More", &n.notes_url);
                }
                output::print_field("Oldest compatible", &n.min_compatible);
                if let Some(a) = n.archive_for(&super::this_platform()) {
                    output::print_field(
                        "Archive",
                        &format!("{} ({} bytes, sha256 {})", a.archive, a.size, a.sha256),
                    );
                }
                output::print_field("Valid until", &format!("{} (unix ms)", n.expires_ms));
                println!(
                    "Nothing was installed. {}",
                    banner::install_hint(std::env::consts::OS, "Install with")
                );
            }
        }
        Ok(())
    }
}

/// `tenzro update notices`
#[derive(Debug, Parser)]
pub struct NoticesCmd {
    /// `on` or `off`: whether banners and status lines about new releases show.
    #[arg(value_parser = ["on", "off"])]
    state: Option<String>,
    #[command(flatten)]
    at: super::Where,
}

impl NoticesCmd {
    pub(super) fn execute(&self) -> Result<()> {
        let data_dir = self.at.data_dir();
        let mut prefs = Prefs::load(&data_dir);
        if let Some(s) = &self.state {
            prefs.notices = s == "on";
            prefs
                .save(&data_dir)
                .with_context(|| "save the notice settings")?;
        }
        output::print_field("Release notices", if prefs.notices { "on" } else { "off" });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_update_notice::Severity;
    use tenzro_update_notice::notice::fixture::{key, notice as sample, signed};

    // The embedded release key signs nothing in tests, so the tests trust a
    // test key through the trusted keys file, as an owner rehearsing would.
    fn install_test_key(dir: &Path) -> tenzro_update_notice::notice::LocalKey {
        let k = key(1);
        std::fs::create_dir_all(dir.join("update")).unwrap();
        std::fs::write(
            dir.join("update/trusted-keys.json"),
            format!(
                r#"{{"targets":["{}"],"timestamp":[]}}"#,
                hex::encode(k.public_sec1())
            ),
        )
        .unwrap();
        k
    }

    fn live_notice(version: &str, severity: Severity) -> Notice {
        let now = now_ms();
        let mut n = sample(version, severity);
        n.released_ms = now - 3_600_000;
        n.issued_ms = now - 1_000;
        n.expires_ms = now + 30 * 24 * 3_600_000;
        n
    }

    #[tokio::test]
    async fn refresh_reads_the_channel_and_keeps_the_notice_for_the_next_run() {
        let data = tempfile::tempdir().unwrap();
        let chan = tempfile::tempdir().unwrap();
        let k = install_test_key(data.path());
        std::fs::write(
            chan.path().join("notice.json"),
            signed(&k, &live_notice("9.9.9", Severity::Security)),
        )
        .unwrap();
        let (n, how) = refresh(data.path(), chan.path().to_str().unwrap(), None, now_ms()).await;
        assert_eq!(how.unwrap(), "the release channel");
        assert_eq!(n.unwrap().version, "9.9.9");
        // A later run reads the cache with no channel at all.
        assert_eq!(cached(data.path(), now_ms()).unwrap().version, "9.9.9");
        // Nothing was installed: a notice only writes under update/.
        let entries: Vec<_> = std::fs::read_dir(data.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("update")]);
    }

    #[tokio::test]
    async fn a_tampered_notice_on_the_channel_is_not_kept() {
        let data = tempfile::tempdir().unwrap();
        let chan = tempfile::tempdir().unwrap();
        install_test_key(data.path());
        // Signed by a key this machine does not trust.
        std::fs::write(
            chan.path().join("notice.json"),
            signed(&key(2), &live_notice("9.9.9", Severity::Normal)),
        )
        .unwrap();
        let (n, how) = refresh(data.path(), chan.path().to_str().unwrap(), None, now_ms()).await;
        assert!(n.is_none() && how.is_err());
        assert!(cached(data.path(), now_ms()).is_none());
    }

    #[test]
    fn the_banner_follows_its_rules_end_to_end() {
        let data = tempfile::tempdir().unwrap();
        let k = install_test_key(data.path());
        offer(
            data.path(),
            &signed(&k, &live_notice("9.9.9", Severity::Normal)),
            now_ms(),
        )
        .unwrap();
        let tty = Surface {
            is_terminal: true,
            quiet: false,
            json: false,
        };
        let line = banner_line(data.path(), None, tty, now_ms()).expect("shown the first time");
        assert!(
            line.contains("9.9.9")
                && line.contains(env!("CARGO_PKG_VERSION"))
                && line.ends_with(&banner::install_hint(std::env::consts::OS, "Run")),
            "{line}"
        );
        assert!(
            banner_line(data.path(), None, tty, now_ms()).is_none(),
            "once per version per day"
        );
        let j = read_status(data.path(), now_ms());
        assert_eq!(j["update_available"], true);
        assert_eq!(j["latest_version"], "9.9.9");
        assert_eq!(j["notice"]["platforms"][0]["platform"], "x86_64-linux");
    }

    #[test]
    fn a_validator_is_told_when_a_restart_is_safe_only_with_an_update_pending() {
        let n = live_notice("9.9.9", Severity::Normal);
        let epoch = Some(EpochView {
            epoch: 5,
            blocks_to_boundary: Some(2),
        });
        assert!(
            restart_line(Some(&n), true, epoch)
                .unwrap()
                .contains("Wait")
        );
        assert!(
            restart_line(Some(&n), false, epoch).is_none(),
            "a machine with no role is not told"
        );
        assert!(restart_line(None, true, epoch).is_none());
    }

    #[test]
    fn notices_off_hides_the_banner_and_survives_a_restart() {
        let data = tempfile::tempdir().unwrap();
        let k = install_test_key(data.path());
        offer(
            data.path(),
            &signed(&k, &live_notice("9.9.9", Severity::Normal)),
            now_ms(),
        )
        .unwrap();
        let cmd = NoticesCmd {
            state: Some("off".into()),
            at: super::super::Where {
                data_dir: Some(data.path().to_path_buf()),
            },
        };
        cmd.execute().unwrap();
        let tty = Surface {
            is_terminal: true,
            quiet: false,
            json: false,
        };
        assert!(banner_line(data.path(), None, tty, now_ms()).is_none());
        assert!(!Prefs::load(data.path()).notices);
    }
}
