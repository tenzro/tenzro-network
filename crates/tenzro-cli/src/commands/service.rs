//! Installing and starting the node service, and watching it sync.
//!
//! `tenzro setup --apply` writes the service unit and then uses this module to
//! put it in place, start it, and follow the node from its first block to the
//! network's tip. Installing a unit is a privileged act on Linux, so the
//! commands run with the terminal attached and `sudo` asks for its own
//! password; nothing here stores or relays one.

use std::path::Path;
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
                format!("/etc/systemd/system/{SYSTEMD_UNIT}"),
            ],
            vec![s("sudo"), s("systemctl"), s("daemon-reload")],
            vec![s("sudo"), s("systemctl"), s("enable"), s("tenzro-node")],
            vec![s("sudo"), s("systemctl"), s("restart"), s("tenzro-node")],
        ]),
        "macos" => {
            let agents = home.join("Library/LaunchAgents");
            let dest = agents.join(format!("{LAUNCHD_LABEL}.plist"));
            Ok(vec![
                vec![s("mkdir"), s("-p"), agents.display().to_string()],
                vec![s("cp"), unit.display().to_string(), dest.display().to_string()],
                // A load of an agent that is already loaded fails; unload
                // first so a re-run replaces it.
                vec![s("launchctl"), s("unload"), dest.display().to_string()],
                vec![s("launchctl"), s("load"), s("-w"), dest.display().to_string()],
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
    for step in install_steps(os, unit, &home)? {
        let (program, args) = step.split_first().expect("a command has a program");
        output::print_info(&format!("$ {}", step.join(" ")));
        let status = std::process::Command::new(program)
            .args(args)
            .status()
            .map_err(|e| anyhow!("could not run `{program}`: {e}"))?;
        let tolerated = program == "launchctl" && args.first().map(String::as_str) == Some("unload");
        if !status.success() && !tolerated {
            bail!("`{}` failed ({status}); the service was not started", step.join(" "));
        }
    }
    Ok(())
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
    let peers: String = rpc.call("net_peerCount", json!([])).await.unwrap_or_default();
    let syncing: Value = rpc.call("tenzro_syncing", json!([])).await.unwrap_or(Value::Bool(false));
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

/// Follow the node at `rpc_url` until it is synced or `limit` passes.
/// Returns the last sample and whether it was caught up.
pub async fn follow_sync(rpc_url: &str, limit: Duration) -> Result<(Option<Sample>, bool)> {
    let rpc = RpcClient::new(rpc_url);
    let spinner = output::create_spinner("Waiting for the node's RPC...");
    let started = Instant::now();
    let mut in_sync = 0u32;
    let mut last = None;
    let mut tick = 0u32;
    while started.elapsed() < limit {
        tick += 1;
        if tick.is_multiple_of(5)
            && let Some(log) = failed_unit_log()
        {
            spinner.finish_and_clear();
            bail!("the node service failed to start. Its log:\n{log}");
        }
        if let Some(s) = sample(&rpc).await {
            spinner.set_message(s.describe());
            in_sync = if s.caught_up() { in_sync + 1 } else { 0 };
            last = Some(s);
            if in_sync >= SYNCED_AFTER {
                spinner.finish_and_clear();
                return Ok((last, true));
            }
        }
        tokio::time::sleep(SAMPLE_EVERY).await;
    }
    spinner.finish_and_clear();
    Ok((last, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_installs_the_unit_and_restarts_it() {
        let steps = install_steps("linux", Path::new("/data/tenzro-node.service"), Path::new("/home/a")).unwrap();
        assert_eq!(
            steps[0],
            ["sudo", "cp", "/data/tenzro-node.service", "/etc/systemd/system/tenzro-node.service"]
        );
        assert!(steps.iter().any(|s| s.join(" ") == "sudo systemctl daemon-reload"));
        assert_eq!(steps.last().unwrap().join(" "), "sudo systemctl restart tenzro-node");
    }

    #[test]
    fn macos_loads_a_launch_agent_from_the_home_directory() {
        let steps = install_steps("macos", Path::new("/data/n.plist"), Path::new("/Users/a")).unwrap();
        let dest = "/Users/a/Library/LaunchAgents/network.tenzro.node.plist";
        assert!(steps.iter().any(|s| s.join(" ") == format!("cp /data/n.plist {dest}")));
        assert_eq!(steps.last().unwrap().join(" "), format!("launchctl load -w {dest}"));
    }

    #[test]
    fn other_systems_are_refused_with_the_manual_route() {
        let err = install_steps("windows", Path::new("u"), Path::new("h")).unwrap_err();
        assert!(err.to_string().contains("tenzro-node"));
    }

    #[test]
    fn a_node_still_behind_the_tip_reports_progress() {
        let s = Sample::from_rpc("0x64", "0x3", &json!({"syncing": true, "currentBlock": "0x64", "highestBlock": "0xc8"}));
        assert!(s.syncing && !s.caught_up());
        assert_eq!((s.height, s.highest, s.peers), (100, 200, 3));
        assert!(s.describe().contains("100 of 200 (50.0%)"), "{}", s.describe());
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
