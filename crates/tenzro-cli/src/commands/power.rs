//! Keeping a node machine awake on mains power, and the one-time steps that
//! let its owner manage it remotely.
//!
//! Nothing here changes the machine unless the owner asks: `tenzro power
//! keep-awake on` (or yes to `tenzro setup`'s question) installs a helper that
//! holds the machine awake while the node runs and only on mains power, and
//! `off` removes it again. `tenzro power remote` only prints.
//!
//! - Linux: a systemd unit bound to the node's unit that holds a
//!   `systemd-inhibit` sleep lock, started only on mains power.
//! - macOS: a launchd agent running `caffeinate -s` for as long as the node
//!   process lives; `-s` holds only on mains power.
//! - Windows: the mains-power sleep timeout set to never with `powercfg`,
//!   the previous value kept so `off` puts it back. Battery settings are not
//!   touched.

use crate::output;
use anyhow::{Result, anyhow, bail};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

/// The keep-awake unit on Linux.
pub const SYSTEMD_UNIT: &str = "tenzro-keep-awake.service";
/// The keep-awake agent's label on macOS.
pub const LAUNCHD_LABEL: &str = "network.tenzro.keep-awake";
/// Where `on` keeps the Windows mains sleep timeout it replaced, in minutes.
const WINDOWS_PREVIOUS: &str = "keep-awake-previous-ac-minutes";

/// The keep-awake unit for Linux. Pure.
pub fn systemd_unit_text() -> String {
    format!(
        "[Unit]
Description=Keep this machine awake while the Tenzro node runs, on mains power (tenzro power keep-awake)
BindsTo={node}
After={node}
ConditionACPower=true

[Service]
ExecStart=/usr/bin/systemd-inhibit --what=sleep:idle --who=tenzro-node --why=\"The Tenzro node is running\" --mode=block /bin/sleep infinity

[Install]
WantedBy={node}
",
        node = super::service::SYSTEMD_UNIT
    )
}

/// The keep-awake agent for macOS: while a `tenzro-node` process runs,
/// `caffeinate -s -w` holds the machine awake on mains power until it exits.
/// Pure.
pub fn launchd_plist_text() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>-c</string>
    <string>while :; do p=$(/usr/bin/pgrep -x tenzro-node) &amp;&amp; /usr/bin/caffeinate -s -w "$p"; sleep 30; done</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
"#
    )
}

fn s(v: &str) -> String {
    v.to_string()
}

/// The commands that turn keep-awake on, for `os` (`std::env::consts::OS`).
/// `file` is the unit or agent `on` wrote; `home` the user's home. Windows
/// takes the minutes to restore from [`windows_ac_minutes`] first. Pure.
pub fn on_steps(os: &str, file: &Path, home: &Path) -> Result<Vec<Vec<String>>> {
    match os {
        "linux" => Ok(vec![
            vec![
                s("sudo"),
                s("cp"),
                file.display().to_string(),
                format!("/etc/systemd/system/{SYSTEMD_UNIT}"),
            ],
            vec![s("sudo"), s("systemctl"), s("daemon-reload")],
            vec![
                s("sudo"),
                s("systemctl"),
                s("enable"),
                s("--now"),
                s(SYSTEMD_UNIT),
            ],
        ]),
        "macos" => {
            let dest = launchd_path(home);
            Ok(vec![
                vec![
                    s("mkdir"),
                    s("-p"),
                    format!("{}/Library/LaunchAgents", home.display()),
                ],
                vec![s("cp"), file.display().to_string(), dest.clone()],
                vec![s("launchctl"), s("unload"), dest.clone()],
                vec![s("launchctl"), s("load"), s("-w"), dest],
            ])
        }
        "windows" => Ok(vec![vec![
            s("powercfg"),
            s("/change"),
            s("standby-timeout-ac"),
            s("0"),
        ]]),
        other => {
            bail!("keeping the machine awake is supported on Linux, macOS and Windows, not {other}")
        }
    }
}

/// The commands that turn keep-awake off again. `previous_ac_minutes` is the
/// Windows mains sleep timeout `on` replaced. Pure.
pub fn off_steps(
    os: &str,
    home: &Path,
    previous_ac_minutes: Option<u32>,
) -> Result<Vec<Vec<String>>> {
    match os {
        "linux" => Ok(vec![
            vec![
                s("sudo"),
                s("systemctl"),
                s("disable"),
                s("--now"),
                s(SYSTEMD_UNIT),
            ],
            vec![
                s("sudo"),
                s("rm"),
                s("-f"),
                format!("/etc/systemd/system/{SYSTEMD_UNIT}"),
            ],
            vec![s("sudo"), s("systemctl"), s("daemon-reload")],
        ]),
        "macos" => {
            let dest = launchd_path(home);
            Ok(vec![
                vec![s("launchctl"), s("unload"), dest.clone()],
                vec![s("rm"), s("-f"), dest],
            ])
        }
        "windows" => {
            let minutes = previous_ac_minutes.ok_or_else(|| {
                anyhow!("the mains sleep timeout before keep-awake was not recorded; set it in Power Options")
            })?;
            Ok(vec![vec![
                s("powercfg"),
                s("/change"),
                s("standby-timeout-ac"),
                minutes.to_string(),
            ]])
        }
        other => {
            bail!("keeping the machine awake is supported on Linux, macOS and Windows, not {other}")
        }
    }
}

fn launchd_path(home: &Path) -> String {
    format!(
        "{}/Library/LaunchAgents/{LAUNCHD_LABEL}.plist",
        home.display()
    )
}

/// The mains sleep timeout in minutes from `powercfg /query SCHEME_CURRENT
/// SUB_SLEEP STANDBYIDLE` output (it states seconds as hex). Pure.
pub fn windows_ac_minutes(query: &str) -> Option<u32> {
    query.lines().find_map(|l| {
        let (key, value) = l.split_once(':')?;
        if !key
            .trim()
            .eq_ignore_ascii_case("Current AC Power Setting Index")
        {
            return None;
        }
        let secs = u32::from_str_radix(value.trim().trim_start_matches("0x"), 16).ok()?;
        Some(secs / 60)
    })
}

/// The one-time steps that let the owner reach, manage and wake this machine
/// from elsewhere, for `os`. Printed only. Pure.
pub fn remote_steps(os: &str) -> Vec<String> {
    match os {
        "windows" => vec![
            s("Remote login (an administrator PowerShell, once):"),
            s(&format!(
                "  Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.{}.0",
                1
            )),
            s("  Set-Service sshd -StartupType Automatic; Start-Service sshd"),
            s(
                "Wake from elsewhere: note the wired adapter's hardware address (getmac /v), then enable",
            ),
            s(
                "  'Wake on Magic Packet' in Device Manager > the adapter > Advanced and Power Management.",
            ),
            s(
                "A remote shell started before Tenzro was installed sees the new PATH once sshd restarts:",
            ),
            s("  Restart-Service sshd"),
        ],
        "macos" => vec![
            s(
                "Remote login: System Settings > General > Sharing > Remote Login (or: sudo systemsetup -setremotelogin on)",
            ),
            s(
                "Wake from elsewhere: sudo pmset -c womp 1, and note the address: networksetup -getmacaddress en0",
            ),
            s(
                "A remote command runs without your login PATH; call it as /usr/local/bin/tenzro, or ssh -t host zsh -lc 'tenzro status'",
            ),
        ],
        _ => vec![
            s("Remote login: sudo systemctl enable --now ssh   (sshd on Fedora and its relatives)"),
            s(
                "Wake from elsewhere: note the address (ip link), then enable wake-on-LAN, for example:",
            ),
            s("  sudo ethtool -s <interface> wol g   (and Wake-on-LAN in the firmware settings)"),
        ],
    }
}

/// Keep this machine awake while the node runs, and how to manage it remotely.
#[derive(Debug, Subcommand)]
pub enum PowerCommand {
    /// Hold the machine awake while the node runs, on mains power only (on), stop (off), or show (status).
    KeepAwake(KeepAwakeCmd),
    /// Print the one-time steps for remote login and wake-on-LAN. Changes nothing.
    Remote,
}

#[derive(Debug, Parser)]
pub struct KeepAwakeCmd {
    #[arg(value_parser = ["on", "off", "status"])]
    action: String,
}

impl PowerCommand {
    pub async fn execute(&self) -> Result<()> {
        let os = std::env::consts::OS;
        match self {
            Self::Remote => {
                for line in remote_steps(os) {
                    println!("{line}");
                }
                Ok(())
            }
            Self::KeepAwake(c) => match c.action.as_str() {
                "on" => keep_awake_on(os),
                "off" => keep_awake_off(os),
                _ => {
                    output::print_info(&status(os));
                    Ok(())
                }
            },
        }
    }
}

fn home() -> Result<PathBuf> {
    tenzro_types::paths::home_dir().ok_or_else(|| anyhow!("no home directory"))
}

/// Install the helper for this machine. Runs the commands with the terminal
/// attached; sudo may ask for a password.
pub fn keep_awake_on(os: &str) -> Result<()> {
    let dir = tenzro_types::paths::tenzro_home();
    std::fs::create_dir_all(&dir).map_err(|e| anyhow!("create {}: {e}", dir.display()))?;
    let file = match os {
        "linux" => Some((dir.join(SYSTEMD_UNIT), systemd_unit_text())),
        "macos" => Some((
            dir.join(format!("{LAUNCHD_LABEL}.plist")),
            launchd_plist_text(),
        )),
        _ => None,
    };
    if let Some((path, text)) = &file {
        std::fs::write(path, text).map_err(|e| anyhow!("write {}: {e}", path.display()))?;
    }
    if os == "windows" {
        let current = windows_query().and_then(|q| windows_ac_minutes(&q));
        let minutes = current.ok_or_else(|| {
            anyhow!("could not read the current mains sleep timeout from powercfg")
        })?;
        let keep = dir.join(WINDOWS_PREVIOUS);
        if !keep.exists() {
            std::fs::write(&keep, minutes.to_string())
                .map_err(|e| anyhow!("write {}: {e}", keep.display()))?;
        }
    }
    let file = file.map(|(p, _)| p).unwrap_or_default();
    run(
        &on_steps(os, &file, &home()?)?,
        "keep-awake was not turned on",
    )?;
    output::print_success(
        "This machine stays awake while the node runs, on mains power. `tenzro power keep-awake off` undoes it.",
    );
    Ok(())
}

/// Remove the helper again.
pub fn keep_awake_off(os: &str) -> Result<()> {
    let keep = tenzro_types::paths::tenzro_home().join(WINDOWS_PREVIOUS);
    let previous = std::fs::read_to_string(&keep)
        .ok()
        .and_then(|t| t.trim().parse().ok());
    run(
        &off_steps(os, &home()?, previous)?,
        "keep-awake was not turned off",
    )?;
    let _ = std::fs::remove_file(&keep);
    output::print_success("Keep-awake is off: the machine sleeps as its own settings say.");
    Ok(())
}

fn status(os: &str) -> String {
    let on = match os {
        "linux" => std::process::Command::new("systemctl")
            .args(["is-enabled", "--quiet", SYSTEMD_UNIT])
            .status()
            .is_ok_and(|s| s.success()),
        "macos" => home().is_ok_and(|h| Path::new(&launchd_path(&h)).exists()),
        "windows" => windows_query().and_then(|q| windows_ac_minutes(&q)) == Some(0),
        _ => false,
    };
    if on {
        s("keep-awake: on (mains power)")
    } else {
        s("keep-awake: off")
    }
}

fn windows_query() -> Option<String> {
    let out = std::process::Command::new("powercfg")
        .args(["/query", "SCHEME_CURRENT", "SUB_SLEEP", "STANDBYIDLE"])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn run(steps: &[Vec<String>], not_done: &str) -> Result<()> {
    for step in steps {
        let (program, args) = step.split_first().expect("a command has a program");
        output::print_info(&format!("$ {}", step.join(" ")));
        let status = std::process::Command::new(program)
            .args(args)
            .status()
            .map_err(|e| anyhow!("could not run `{program}`: {e}"))?;
        let tolerated =
            program == "launchctl" && args.first().map(String::as_str) == Some("unload");
        if !status.success() && !tolerated {
            bail!("`{}` failed ({status}); {not_done}", step.join(" "));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_linux_unit_holds_sleep_only_with_the_node_and_on_mains_power() {
        let unit = systemd_unit_text();
        assert!(unit.contains("BindsTo=tenzro-node.service"));
        assert!(unit.contains("WantedBy=tenzro-node.service"));
        assert!(unit.contains("ConditionACPower=true"));
        assert!(unit.contains("systemd-inhibit --what=sleep:idle"));
        assert!(unit.contains("--mode=block"));
    }

    #[test]
    fn the_macos_agent_holds_sleep_only_while_the_node_lives_and_on_mains_power() {
        let plist = launchd_plist_text();
        assert!(
            plist.contains("caffeinate -s -w"),
            "-s holds only on mains power, -w ends with the node"
        );
        assert!(plist.contains("pgrep -x tenzro-node"));
        assert!(plist.contains(LAUNCHD_LABEL));
        assert!(!plist.contains("&&"), "the shell line is escaped for XML");
    }

    #[test]
    fn every_on_has_an_off_that_undoes_it() {
        let home = Path::new("/home/op");
        for os in ["linux", "macos", "windows"] {
            let on = on_steps(os, Path::new("/x/f"), home).unwrap();
            let off = off_steps(os, home, Some(30)).unwrap();
            assert!(!on.is_empty() && !off.is_empty(), "{os}");
        }
        let on = on_steps("linux", Path::new("/x/f"), home).unwrap();
        assert!(on.contains(&vec![
            s("sudo"),
            s("systemctl"),
            s("enable"),
            s("--now"),
            s(SYSTEMD_UNIT)
        ]));
        let off = off_steps("linux", home, None).unwrap();
        assert!(off.contains(&vec![
            s("sudo"),
            s("systemctl"),
            s("disable"),
            s("--now"),
            s(SYSTEMD_UNIT)
        ]));
        assert_eq!(
            off_steps("windows", home, Some(30)).unwrap(),
            vec![vec![
                s("powercfg"),
                s("/change"),
                s("standby-timeout-ac"),
                s("30")
            ]]
        );
        assert!(
            off_steps("windows", home, None).is_err(),
            "no recorded value, nothing guessed"
        );
        assert!(on_steps("freebsd", Path::new("/x"), home).is_err());
    }

    #[test]
    fn windows_changes_only_the_mains_timeout() {
        let on = on_steps("windows", Path::new(""), Path::new("C:/Users/op")).unwrap();
        assert_eq!(
            on,
            vec![vec![
                s("powercfg"),
                s("/change"),
                s("standby-timeout-ac"),
                s("0")
            ]]
        );
        assert!(
            on.iter().flatten().all(|a| !a.contains("-dc")),
            "battery settings are not touched"
        );
    }

    #[test]
    fn the_mains_timeout_is_read_from_powercfg() {
        let q = "Power Setting GUID: 29f6c1db-86da-48c5-9fdb-f2b67b1f44da  (Sleep after)\n    \
                 Current AC Power Setting Index: 0x00000708\n    Current DC Power Setting Index: 0x00000384\n";
        assert_eq!(windows_ac_minutes(q), Some(30));
        assert_eq!(
            windows_ac_minutes("Current AC Power Setting Index: 0x00000000"),
            Some(0)
        );
        assert_eq!(windows_ac_minutes("nothing here"), None);
    }

    #[test]
    fn the_remote_steps_only_print() {
        for os in ["linux", "macos", "windows"] {
            assert!(!remote_steps(os).is_empty());
        }
        assert!(
            remote_steps("windows")
                .iter()
                .any(|l| l.contains("Restart-Service sshd"))
        );
    }
}
