//! Installing, starting and restarting the node service, and watching it sync.
//!
//! `tenzro setup --apply` writes the service unit and then uses this module to
//! put it in place, start it, and follow the node from its first block to the
//! network's tip. Installing a unit is a privileged act on Linux, so the
//! commands run with the terminal attached and `sudo` asks for its own
//! password; nothing here stores or relays one.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use crate::output;

use crate::rpc::{RpcClient, parse_hex_u64};

/// Name of the installed systemd unit.
pub const SYSTEMD_UNIT: &str = "tenzro-node.service";

/// Launchd label of the installed agent.
pub const LAUNCHD_LABEL: &str = "network.tenzro.node";

/// How often the node is sampled while syncing.
const SAMPLE_EVERY: Duration = Duration::from_secs(2);

/// Consecutive in-sync samples that count as synced. One sample can land in
/// the gap between two blocks.
const SYNCED_AFTER: u32 = 3;

/// How long to follow a sync before handing the operator a command to follow
/// it themselves.
pub const FOLLOW_FOR: Duration = Duration::from_secs(15 * 60);

/// The commands that install `unit` and (re)start the node, for `os`
/// (`std::env::consts::OS`). Each inner list is one command. Pure.
pub fn install_steps(os: &str, unit: &Path, home: &Path) -> Result<Vec<Vec<String>>> {
    let s = |v: &str| v.to_string();
    match os {
        "linux" => Ok(vec![
            vec![
                s("sudo"),
                s("cp"),
                unit.display().to_string(),
                systemd_unit_path().display().to_string(),
            ],
            vec![s("sudo"), s("systemctl"), s("daemon-reload")],
            vec![s("sudo"), s("systemctl"), s("enable"), s("tenzro-node")],
            vec![s("sudo"), s("systemctl"), s("restart"), s("tenzro-node")],
        ]),
        "macos" => {
            let agents = launchd_agents_dir(home);
            let dest = launchd_plist_path(home);
            Ok(vec![
                vec![s("mkdir"), s("-p"), agents.display().to_string()],
                vec![
                    s("cp"),
                    unit.display().to_string(),
                    dest.display().to_string(),
                ],
                // A load of an agent that is already loaded fails; unload
                // first so a re-run replaces it.
                vec![s("launchctl"), s("unload"), dest.display().to_string()],
                vec![
                    s("launchctl"),
                    s("load"),
                    s("-w"),
                    dest.display().to_string(),
                ],
            ])
        }
        other => bail!(
            "installing the service is supported on Linux and macOS, not {other}; \
             start the node with `tenzro-node` directly"
        ),
    }
}

/// Run the install commands in order, with the terminal attached. A failed
/// `launchctl unload` is expected when nothing was loaded and is ignored.
pub fn install(os: &str, unit: &Path) -> Result<()> {
    let home = tenzro_types::paths::home_dir().ok_or_else(|| anyhow!("no home directory"))?;
    run_steps(
        &install_steps(os, unit, &home)?,
        "the service was not started",
    )
}

/// Runs `steps` in order, with the terminal attached, and stops at the first
/// that fails. `not_done` ends the error and says what was left undone.
fn run_steps(steps: &[Vec<String>], not_done: &str) -> Result<()> {
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

/// Where the installed systemd unit is.
fn systemd_unit_path() -> PathBuf {
    PathBuf::from(format!("/etc/systemd/system/{SYSTEMD_UNIT}"))
}

/// Where the installed launchd agent is, under `home`.
fn launchd_plist_path(home: &Path) -> PathBuf {
    PathBuf::from(format!(
        "{}/{LAUNCHD_LABEL}.plist",
        launchd_agents_dir(home).display()
    ))
}

/// The launchd agents folder under `home`. It is a POSIX path whichever
/// system computes it, so it is joined with `/` and never the host separator.
fn launchd_agents_dir(home: &Path) -> PathBuf {
    let home = home.display().to_string();
    PathBuf::from(format!(
        "{}/Library/LaunchAgents",
        home.trim_end_matches('/')
    ))
}

/// The node service `tenzro setup` installs, as found on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeService {
    /// The systemd unit at this path, with the node running under it.
    Systemd(PathBuf),
    /// The launchd agent loaded from this plist.
    Launchd(PathBuf),
    /// The node does not run under an installed service here.
    None,
}

/// Whether `program` ran with `args` and reported success. Its output is not shown.
fn succeeds(program: &str, args: &[&str]) -> bool {
    std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Finds the node service on this machine, for `os` (`std::env::consts::OS`).
/// A unit that is installed and not running does not count: restarting it
/// would start a node its operator stopped, or a second node beside one
/// started by hand.
pub fn installed(os: &str) -> NodeService {
    match os {
        "linux" => {
            let unit = systemd_unit_path();
            if unit.is_file() && succeeds("systemctl", &["is-active", "--quiet", SYSTEMD_UNIT]) {
                NodeService::Systemd(unit)
            } else {
                NodeService::None
            }
        }
        "macos" => {
            let Some(home) = tenzro_types::paths::home_dir() else {
                return NodeService::None;
            };
            let plist = launchd_plist_path(&home);
            if plist.is_file() && succeeds("launchctl", &["list", LAUNCHD_LABEL]) {
                NodeService::Launchd(plist)
            } else {
                NodeService::None
            }
        }
        _ => NodeService::None,
    }
}

/// The commands that restart the node through `service`. Pure. The launchd
/// agent is unloaded and loaded again, the way [`install_steps`] loaded it.
pub fn restart_steps(service: &NodeService) -> Result<Vec<Vec<String>>> {
    let s = |v: &str| v.to_string();
    match service {
        NodeService::Systemd(_) => Ok(vec![vec![
            s("sudo"),
            s("systemctl"),
            s("restart"),
            s("tenzro-node"),
        ]]),
        NodeService::Launchd(plist) => Ok(vec![
            vec![s("launchctl"), s("unload"), plist.display().to_string()],
            vec![
                s("launchctl"),
                s("load"),
                s("-w"),
                plist.display().to_string(),
            ],
        ]),
        NodeService::None => {
            bail!("the node does not run under an installed service on this machine")
        }
    }
}

/// Restart the node through its service, with the terminal attached, so
/// `sudo` asks for its own password on Linux.
pub fn restart(service: &NodeService) -> Result<()> {
    run_steps(
        &restart_steps(service)?,
        "the node service was not restarted",
    )
}

/// The program the installed `service` starts, read from its unit. `None`
/// when that cannot be read with certainty.
pub fn program(service: &NodeService) -> Option<PathBuf> {
    match service {
        NodeService::Systemd(unit) => {
            // A drop-in can replace what the unit starts.
            let mut drop_ins = unit.clone().into_os_string();
            drop_ins.push(".d");
            if let Ok(entries) = std::fs::read_dir(PathBuf::from(drop_ins)) {
                for entry in entries.flatten() {
                    if std::fs::read_to_string(entry.path())
                        .is_ok_and(|text| text.contains("ExecStart="))
                    {
                        return None;
                    }
                }
            }
            systemd_program(&std::fs::read_to_string(unit).ok()?)
        }
        NodeService::Launchd(plist) => launchd_program(&std::fs::read_to_string(plist).ok()?),
        NodeService::None => None,
    }
}

/// The program a systemd unit starts: the first word of its `ExecStart=`. Pure.
pub fn systemd_program(unit: &str) -> Option<PathBuf> {
    // A later `ExecStart=` replaces an earlier one, and an empty one clears it.
    let command = unit.lines().rev().find_map(|l| {
        l.trim()
            .strip_prefix("ExecStart=")
            .map(str::trim)
            .filter(|v| !v.is_empty())
    })?;
    let command = command.trim_start_matches(['-', '@', ':', '+', '!']);
    let program = match command.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next()?,
        None => command.split_whitespace().next()?,
    };
    Some(PathBuf::from(program))
}

/// What the launchd agent runs: count this start against an open update
/// trial, then become the node. `$1` is `tenzro`, `$2` the install directory,
/// `$3` the data directory, and the rest is the node and its arguments. The
/// count's result is not looked at, so a count that fails never holds the
/// node back. `exec` leaves launchd watching the node itself.
pub const LAUNCHD_START: &str =
    r#""$1" update boot-check --install-dir "$2" --data-dir "$3"; shift 3; exec "$@""#;

/// The `ProgramArguments` of the launchd agent. Every path and argument is
/// handed to the shell as its own word, so none of them is ever parsed. Pure.
pub fn launchd_arguments(
    tenzro: &str,
    install_dir: &str,
    data_dir: &str,
    node: &str,
    node_args: &[String],
) -> Vec<String> {
    let mut out: Vec<String> = [
        "/bin/sh",
        "-c",
        LAUNCHD_START,
        "sh",
        tenzro,
        install_dir,
        data_dir,
        node,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    out.extend(node_args.iter().cloned());
    out
}

/// Text as it is written inside an XML element.
pub fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn xml_unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// The `ProgramArguments` strings of a launchd plist, in order. Pure.
pub fn launchd_program_arguments(plist: &str) -> Option<Vec<String>> {
    let after = plist.split_once("<key>ProgramArguments</key>")?.1;
    let mut rest = after.split_once("<array>")?.1.split_once("</array>")?.0;
    let mut out = Vec::new();
    while let Some((_, tail)) = rest.split_once("<string>") {
        let (value, tail) = tail.split_once("</string>")?;
        out.push(xml_unescape(value));
        rest = tail;
    }
    Some(out)
}

/// The node a launchd agent starts: the program behind [`LAUNCHD_START`], or
/// the first argument of an agent that starts its program directly. `None`
/// for any other shell command, which is not read. Pure.
pub fn launchd_program(plist: &str) -> Option<PathBuf> {
    let args = launchd_program_arguments(plist)?;
    match args.as_slice() {
        [sh, c, script, _, _, _, _, node, ..]
            if sh == "/bin/sh" && c == "-c" && script == LAUNCHD_START =>
        {
            Some(PathBuf::from(node))
        }
        [sh, ..] if sh == "/bin/sh" => None,
        [program, ..] => Some(PathBuf::from(program)),
        [] => None,
    }
}

/// One reading of the node's chain position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    pub height: u64,
    /// The network's tip as far as the node knows. Equal to `height` once
    /// caught up.
    pub highest: u64,
    pub peers: u64,
    pub syncing: bool,
}

impl Sample {
    /// Build a sample from the three RPC answers: `eth_blockNumber`,
    /// `net_peerCount` (both hex) and `tenzro_syncing` (`false`, or an object
    /// with `currentBlock` and `highestBlock`).
    pub fn from_rpc(block: &str, peers: &str, syncing: &Value) -> Self {
        let height = parse_hex_u64(block);
        let (syncing_now, highest) = match syncing {
            Value::Object(o) => (
                true,
                o.get("highestBlock")
                    .and_then(Value::as_str)
                    .map(parse_hex_u64)
                    .unwrap_or(height)
                    .max(height),
            ),
            _ => (false, height),
        };
        Self {
            height,
            highest,
            peers: parse_hex_u64(peers),
            syncing: syncing_now,
        }
    }

    /// Whether this reading looks caught up: not syncing, past genesis, and
    /// connected to at least one peer.
    pub fn caught_up(&self) -> bool {
        !self.syncing && self.height > 0 && self.peers > 0
    }

    /// The line shown while waiting.
    pub fn describe(&self) -> String {
        if self.syncing && self.highest > 0 {
            let pct = (self.height as f64 / self.highest as f64 * 100.0).min(100.0);
            format!(
                "syncing: block {} of {} ({pct:.1}%), {} peer(s)",
                self.height, self.highest, self.peers
            )
        } else if self.peers == 0 {
            format!("block {}, no peers yet", self.height)
        } else {
            format!("block {}, {} peer(s)", self.height, self.peers)
        }
    }
}

/// Read one sample from the node, or `None` while its RPC is not up yet.
pub async fn sample(rpc: &RpcClient) -> Option<Sample> {
    let block: String = rpc.call("eth_blockNumber", json!([])).await.ok()?;
    let peers: String = rpc
        .call("net_peerCount", json!([]))
        .await
        .unwrap_or_default();
    let syncing: Value = rpc
        .call("tenzro_syncing", json!([]))
        .await
        .unwrap_or(Value::Bool(false));
    Some(Sample::from_rpc(&block, &peers, &syncing))
}

/// Whether the systemd unit has failed, and if so its last log lines.
fn failed_unit_log() -> Option<String> {
    if std::env::consts::OS != "linux" {
        return None;
    }
    let state = std::process::Command::new("systemctl")
        .args(["is-active", "tenzro-node"])
        .output()
        .ok()?;
    if String::from_utf8_lossy(&state.stdout).trim() != "failed" {
        return None;
    }
    let log = std::process::Command::new("journalctl")
        .args(["-u", "tenzro-node", "-n", "20", "--no-pager"])
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&log.stdout).into_owned())
}

impl Sample {
    /// The short status line shown beside the sync count.
    pub fn note(&self) -> String {
        if self.peers == 0 {
            "waiting for peers".to_string()
        } else if self.height == 0 && !self.syncing {
            format!("{} peer(s), waiting for the first block", self.peers)
        } else {
            format!("{} peer(s)", self.peers)
        }
    }
}

/// Show one reading on the sync count, making the count the first time.
fn show_sample(task: &mut Option<crate::progress::Task>, s: &Sample) {
    let t = task.get_or_insert_with(|| {
        crate::progress::global().count("Syncing the chain", None, "blocks")
    });
    if s.syncing && s.highest > 0 {
        t.set_total(s.highest);
    }
    t.set(s.height);
    t.message(&s.note());
}

/// Follow the node at `rpc_url` until it is synced or `limit` passes.
/// Returns the last sample and whether it was caught up.
///
/// Two things are shown: a wait while the node starts, then a block count
/// that fills as the node syncs (a restore from a snapshot shows the same
/// way, as the height climbs).
pub async fn follow_sync(rpc_url: &str, limit: Duration) -> Result<(Option<Sample>, bool)> {
    let rpc = RpcClient::new(rpc_url);
    let mut starting =
        Some(crate::progress::global().wait("Starting the node", "waiting for its RPC to answer"));
    let mut syncing: Option<crate::progress::Task> = None;
    let started = Instant::now();
    let mut in_sync = 0u32;
    let mut last = None;
    let mut tick = 0u32;
    while started.elapsed() < limit {
        tick += 1;
        if tick.is_multiple_of(5)
            && let Some(log) = failed_unit_log()
        {
            if let Some(t) = starting.take() {
                t.fail("the node service failed to start");
            }
            if let Some(t) = syncing.take() {
                t.fail("the node service failed");
            }
            bail!("the node service failed to start. Its log:\n{log}");
        }
        if let Some(s) = sample(&rpc).await {
            if let Some(t) = starting.take() {
                t.finish_with("the node answers");
            }
            show_sample(&mut syncing, &s);
            in_sync = if s.caught_up() { in_sync + 1 } else { 0 };
            let caught_up = in_sync >= SYNCED_AFTER;
            last = Some(s);
            if caught_up {
                if let Some(t) = syncing.take() {
                    t.finish_with(&format!(
                        "caught up at block {}",
                        last.as_ref().map_or(0, |s| s.height)
                    ));
                }
                return Ok((last, true));
            }
        }
        tokio::time::sleep(SAMPLE_EVERY).await;
    }
    if let Some(t) = starting.take() {
        t.fail("the node did not answer in time");
    }
    if let Some(t) = syncing.take() {
        t.finish_with(&format!(
            "still syncing at block {}",
            last.as_ref().map_or(0, |s| s.height)
        ));
    }
    Ok((last, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_restart_goes_through_the_unit_install_put_in_place() {
        let unit = NodeService::Systemd(systemd_unit_path());
        assert_eq!(
            restart_steps(&unit).unwrap(),
            vec![vec!["sudo", "systemctl", "restart", "tenzro-node"]]
        );
        let home = Path::new("/Users/a");
        let plist = launchd_plist_path(home);
        assert_eq!(
            restart_steps(&NodeService::Launchd(plist.clone())).unwrap(),
            vec![
                vec![
                    "launchctl",
                    "unload",
                    "/Users/a/Library/LaunchAgents/network.tenzro.node.plist"
                ],
                vec![
                    "launchctl",
                    "load",
                    "-w",
                    "/Users/a/Library/LaunchAgents/network.tenzro.node.plist"
                ],
            ]
        );
        assert!(restart_steps(&NodeService::None).is_err());

        // The same unit and the same agent the install commands name.
        let installed_unit =
            install_steps("linux", Path::new("/d/tenzro-node.service"), home).unwrap();
        assert_eq!(
            installed_unit[0][3],
            systemd_unit_path().display().to_string()
        );
        assert_eq!(installed_unit[3], restart_steps(&unit).unwrap()[0]);
        let installed_agent =
            install_steps("macos", Path::new("/d/network.tenzro.node.plist"), home).unwrap();
        assert_eq!(
            installed_agent[2..],
            restart_steps(&NodeService::Launchd(plist)).unwrap()[..]
        );
    }

    #[test]
    fn no_service_is_found_on_a_system_setup_installs_none_for() {
        assert_eq!(installed("windows"), NodeService::None);
        assert_eq!(program(&NodeService::None), None);
    }

    #[test]
    fn the_program_of_a_systemd_unit_is_read_from_its_last_exec_start() {
        let unit = "[Service]\nUser=a\nExecStartPre=-/opt/t/current/bin/tenzro update boot-check\nExecStart=/opt/t/current/bin/tenzro-node --roles user\nRestart=on-failure\n";
        assert_eq!(
            systemd_program(unit),
            Some(PathBuf::from("/opt/t/current/bin/tenzro-node"))
        );
        let replaced = "[Service]\nExecStart=/old/tenzro-node\nExecStart=\nExecStart=-\"/new dir/tenzro-node\" --roles user\n";
        assert_eq!(
            systemd_program(replaced),
            Some(PathBuf::from("/new dir/tenzro-node"))
        );
        assert_eq!(systemd_program("[Service]\nExecStartPre=/bin/true\n"), None);
    }

    #[test]
    fn the_program_of_a_launchd_agent_is_the_node_behind_the_start_count() {
        let strings = |args: &[String]| {
            args.iter()
                .map(|a| format!("<string>{}</string>", xml_escape(a)))
                .collect::<String>()
        };
        let plist = |args: &[String]| {
            format!(
                "<dict><key>Label</key><string>x</string><key>ProgramArguments</key><array>{}</array><key>KeepAlive</key><true/></dict>",
                strings(args)
            )
        };
        let node_args = vec!["--name".to_string(), "a <b> & c".to_string()];
        let wrapped = launchd_arguments(
            "/opt/t/current/bin/tenzro",
            "/opt/t",
            "/Users/a/.tenzro",
            "/opt/t/current/bin/tenzro-node",
            &node_args,
        );
        let text = plist(&wrapped);
        assert_eq!(
            launchd_program_arguments(&text).unwrap(),
            wrapped,
            "every argument survives the plist"
        );
        assert_eq!(
            launchd_program(&text),
            Some(PathBuf::from("/opt/t/current/bin/tenzro-node"))
        );

        let direct = vec![
            "/usr/local/bin/tenzro-node".to_string(),
            "--roles".to_string(),
            "user".to_string(),
        ];
        assert_eq!(
            launchd_program(&plist(&direct)),
            Some(PathBuf::from("/usr/local/bin/tenzro-node"))
        );
        let other_shell = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "exec /somewhere/tenzro-node".to_string(),
        ];
        assert_eq!(
            launchd_program(&plist(&other_shell)),
            None,
            "a shell command it did not write is not read"
        );
        assert_eq!(launchd_program("<dict></dict>"), None);
    }

    /// The launchd start line, run by a real shell: a count that fails does
    /// not stop the node, and every argument reaches the node as one word.
    #[cfg(unix)]
    #[test]
    fn the_launchd_start_line_runs_the_node_after_a_start_count_that_fails() {
        let node_args = vec![
            "%s|%s|".to_string(),
            "two words".to_string(),
            "it's \"quoted\" $HOME".to_string(),
        ];
        let args = launchd_arguments("false", "/install dir", "/data dir", "printf", &node_args);
        let out = std::process::Command::new(&args[0])
            .args(&args[1..])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "two words|it's \"quoted\" $HOME|"
        );

        // The count is given the install and data directories, each as one word.
        let args = launchd_arguments("printf", "/install dir", "/data dir", "true", &[]);
        let out = std::process::Command::new(&args[0])
            .args(&args[1..])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "update");
    }

    #[test]
    fn linux_installs_the_unit_and_restarts_it() {
        let steps = install_steps(
            "linux",
            Path::new("/data/tenzro-node.service"),
            Path::new("/home/a"),
        )
        .unwrap();
        assert_eq!(
            steps[0],
            [
                "sudo",
                "cp",
                "/data/tenzro-node.service",
                "/etc/systemd/system/tenzro-node.service"
            ]
        );
        assert!(
            steps
                .iter()
                .any(|s| s.join(" ") == "sudo systemctl daemon-reload")
        );
        assert_eq!(
            steps.last().unwrap().join(" "),
            "sudo systemctl restart tenzro-node"
        );
    }

    #[test]
    fn macos_loads_a_launch_agent_from_the_home_directory() {
        let steps =
            install_steps("macos", Path::new("/data/n.plist"), Path::new("/Users/a")).unwrap();
        let dest = "/Users/a/Library/LaunchAgents/network.tenzro.node.plist";
        assert!(
            steps
                .iter()
                .any(|s| s.join(" ") == format!("cp /data/n.plist {dest}"))
        );
        assert_eq!(
            steps.last().unwrap().join(" "),
            format!("launchctl load -w {dest}")
        );
    }

    #[test]
    fn other_systems_are_refused_with_the_manual_route() {
        let err = install_steps("windows", Path::new("u"), Path::new("h")).unwrap_err();
        assert!(err.to_string().contains("tenzro-node"));
    }

    #[test]
    fn a_node_still_behind_the_tip_reports_progress() {
        let s = Sample::from_rpc(
            "0x64",
            "0x3",
            &json!({"syncing": true, "currentBlock": "0x64", "highestBlock": "0xc8"}),
        );
        assert!(s.syncing && !s.caught_up());
        assert_eq!((s.height, s.highest, s.peers), (100, 200, 3));
        assert!(
            s.describe().contains("100 of 200 (50.0%)"),
            "{}",
            s.describe()
        );
    }

    #[test]
    fn the_sync_note_says_what_the_node_is_waiting_for() {
        let s = |height, highest, peers, syncing| Sample {
            height,
            highest,
            peers,
            syncing,
        };
        assert_eq!(s(0, 0, 0, false).note(), "waiting for peers");
        assert_eq!(
            s(0, 0, 2, false).note(),
            "2 peer(s), waiting for the first block"
        );
        assert_eq!(s(40, 100, 3, true).note(), "3 peer(s)");
    }

    #[test]
    fn a_node_at_the_tip_with_peers_is_caught_up() {
        let s = Sample::from_rpc("0x2710", "0x5", &Value::Bool(false));
        assert!(s.caught_up());
        assert_eq!(s.describe(), "block 10000, 5 peer(s)");
    }

    #[test]
    fn a_node_with_no_peers_or_no_blocks_is_not_caught_up() {
        assert!(!Sample::from_rpc("0x2710", "0x0", &Value::Bool(false)).caught_up());
        assert!(!Sample::from_rpc("0x0", "0x4", &Value::Bool(false)).caught_up());
        assert_eq!(
            Sample::from_rpc("0x5", "0x0", &Value::Bool(false)).describe(),
            "block 5, no peers yet"
        );
    }
}
