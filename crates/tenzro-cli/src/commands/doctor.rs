//! `tenzro doctor`: everything that has to be true for Tenzro to work on
//! this machine, one line each, and the fix under every line that is not.
//!
//! The checks that need the machine (`gather`) are separate from the verdicts
//! (`evaluate`), which are pure and tested.

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use serde_json::json;

use crate::commands::preflight::{self, Check, Facts, Level};
use crate::output::colors;

/// Check this machine and the network, and say how to fix what is wrong
#[derive(Debug, Parser)]
pub struct DoctorCmd {
    /// Print one JSON object for support instead of the checklist.
    #[arg(long)]
    json: bool,
}

/// What `gather` read.
#[derive(Debug, Clone, Default)]
pub struct Observed {
    pub cli_version: String,
    pub cli_path: Option<PathBuf>,
    pub node_path: Option<PathBuf>,
    pub node_version: Option<String>,
    pub cli_on_path: Option<PathBuf>,
    pub glibc: Option<String>,
    pub node_build: Option<crate::tui::detect::NodeBuild>,
    pub gpus: Vec<String>,
    pub config_exists: bool,
    pub endpoint: String,
    pub endpoint_source: &'static str,
    pub net: Option<crate::tui::detect::Net>,
    pub local_node: Option<bool>,
    pub disk_free_gb: f64,
    pub data_dir: PathBuf,
}

/// The `major.minor` of a version string such as `tenzro-node 0.2.1`.
pub fn major_minor(s: &str) -> Option<(u32, u32)> {
    let v = s.split_whitespace().find(|w| w.chars().next().is_some_and(|c| c.is_ascii_digit()))?;
    let mut it = v.split('.');
    Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
}

fn c(label: &'static str, level: Level, detail: impl Into<String>, fix: &[&str]) -> Check {
    Check { label, level, detail: detail.into(), fix: fix.iter().map(|s| s.to_string()).collect() }
}

/// Turn what was read into the checklist. Pure.
pub fn evaluate(o: &Observed, facts: &Facts) -> Vec<Check> {
    use crate::tui::detect::Net;
    let mut v = Vec::new();
    v.push(c(
        "Version",
        Level::Pass,
        format!(
            "tenzro {} at {}",
            o.cli_version,
            o.cli_path.as_ref().map_or("?".into(), |p| p.display().to_string())
        ),
        &[],
    ));
    v.push(match (&o.cli_on_path, &o.cli_path) {
        (None, _) => c("On PATH", Level::Warn, "tenzro is not on PATH", &["Open a new terminal after installing, or add its folder to PATH."]),
        (Some(p), Some(me)) if p.canonicalize().ok() != me.canonicalize().ok() => c(
            "On PATH",
            Level::Warn,
            format!("`tenzro` on PATH is {}, not this one", p.display()),
            &["Two installs are present; remove the one you do not want."],
        ),
        (Some(p), _) => c("On PATH", Level::Pass, p.display().to_string(), &[]),
    });
    v.push(match (&o.node_path, &o.node_version) {
        (None, _) => c(
            "tenzro-node",
            Level::Fail,
            "not found next to tenzro or on PATH",
            &["Install the Tenzro package for this machine; it puts tenzro and tenzro-node together."],
        ),
        (Some(p), Some(ver)) => match (major_minor(ver), major_minor(&o.cli_version)) {
            (Some(a), Some(b)) if a != b => c(
                "tenzro-node",
                Level::Warn,
                format!("{ver} at {}; tenzro is {}: different release lines", p.display(), o.cli_version),
                &["Install the tenzro and tenzro-node of one release."],
            ),
            _ => c("tenzro-node", Level::Pass, format!("{ver} at {}", p.display()), &[]),
        },
        (Some(p), None) => c("tenzro-node", Level::Warn, format!("{}, but it did not report a version", p.display()), &[]),
    });
    // The hardware key, from the same checks `tenzro setup` uses.
    for chk in preflight::evaluate(facts) {
        if chk.label != "tenzro-node" {
            v.push(chk);
        }
    }
    if let Some(g) = &o.glibc {
        let ok = major_minor(g).is_some_and(|(a, b)| (a, b) >= (2, 39));
        v.push(if ok {
            c("glibc", Level::Pass, g.clone(), &[])
        } else {
            c("glibc", Level::Warn, format!("{g}: the release builds need 2.39 or newer"), &["Use Ubuntu 24.04 or newer, Debian 13 or newer, or Fedora 40 or newer."])
        });
    }
    v.push(match &o.node_build {
        Some(b) if b.startup_ok => c("Build and graphics", Level::Pass, format!("{} build; {}", b.flavour, if o.gpus.is_empty() { "no GPU".to_string() } else { o.gpus.join(", ") }), &[]),
        Some(b) => c(
            "Build and graphics",
            Level::Fail,
            format!("this {} build would refuse to start here: {}", b.flavour, b.refusal.clone().unwrap_or_default()),
            &["Install the CUDA package on an NVIDIA GPU machine, the CPU package otherwise."],
        ),
        None => c("Build and graphics", Level::Warn, "tenzro-node did not answer its hardware check", &[]),
    });
    v.push(if o.config_exists {
        c("Settings", Level::Pass, crate::config::config_path().display().to_string(), &[])
    } else {
        c("Settings", Level::Warn, "no settings file yet: this machine is not set up", &["Run: tenzro"])
    });
    v.push(match &o.net {
        Some(Net::Reachable { chain_id }) => c("Endpoint", Level::Pass, format!("{} ({}) answers, chain {chain_id}", o.endpoint, o.endpoint_source), &[]),
        Some(Net::NotResolving) => c(
            "Endpoint",
            Level::Warn,
            format!("{} ({}): the name does not resolve", o.endpoint, o.endpoint_source),
            &["If this is the public network, it is not reachable yet.", "Try Tenzro on this machine: tenzro dev"],
        ),
        Some(Net::NotAnswering { reason }) => c(
            "Endpoint",
            Level::Warn,
            format!("{} ({}) did not answer: {reason}", o.endpoint, o.endpoint_source),
            &["Check the address and this machine's connection, or try: tenzro dev"],
        ),
        _ => c("Endpoint", Level::Warn, format!("{} not checked", o.endpoint), &[]),
    });
    v.push(match o.local_node {
        Some(true) => c("Local node", Level::Pass, "a node answers on this machine", &[]),
        Some(false) => c("Local node", Level::Pass, "no node is running here (only needed to provide or validate)", &[]),
        None => c("Local node", Level::Warn, "not checked", &[]),
    });
    v.push(if o.disk_free_gb >= 20.0 || o.disk_free_gb == 0.0 {
        c("Disk space", Level::Pass, format!("{:.0} GB free", o.disk_free_gb), &[])
    } else {
        c("Disk space", Level::Warn, format!("{:.0} GB free at {}", o.disk_free_gb, o.data_dir.display()), &["Free some space, or use --data-dir on a bigger disk."])
    });
    v
}

/// The verdict as JSON, for support.
pub fn to_json(o: &Observed, checks: &[Check]) -> serde_json::Value {
    json!({
        "version": o.cli_version,
        "endpoint": o.endpoint,
        "endpoint_source": o.endpoint_source,
        "failed": checks.iter().filter(|c| c.level == Level::Fail).count(),
        "checks": checks.iter().map(|c| json!({
            "label": c.label,
            "status": match c.level { Level::Pass => "ok", Level::Warn => "note", Level::Fail => "fail", Level::Todo => "todo" },
            "detail": c.detail,
            "fix": c.fix,
        })).collect::<Vec<_>>(),
    })
}

fn glibc_version() -> Option<String> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let out = std::process::Command::new("ldd").arg("--version").output().ok()?;
    let first = String::from_utf8_lossy(&out.stdout).lines().next()?.to_string();
    first.split_whitespace().last().map(str::to_string)
}

async fn gather() -> (Observed, Facts) {
    let hw = crate::commands::hardware::detect_hardware_profile().await;
    let se = crate::commands::setup::has_secure_enclave(&hw);
    let facts = tokio::task::spawn_blocking(move || Facts::probe(se)).await.unwrap_or_else(|_| Facts::probe(se));
    let node_path = facts.node_binary.clone();
    let node_version = node_path.clone().and_then(|p| {
        let out = std::process::Command::new(p).arg("--version").output().ok()?;
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    });
    let node_build = match node_path.clone() {
        Some(p) => tokio::task::spawn_blocking(move || {
            let out = std::process::Command::new(p).arg("hardware").output().ok()?;
            crate::tui::detect::parse_node_hardware(&String::from_utf8_lossy(&out.stdout))
        })
        .await
        .ok()
        .flatten(),
        None => None,
    };
    let (endpoint, src) = crate::endpoint::resolve();
    let net = crate::tui::detect::check_network(&endpoint).await;
    let local = crate::tui::detect::check_network(crate::endpoint::LOCAL_RPC).await.is_reachable();
    let obs = Observed {
        cli_version: env!("CARGO_PKG_VERSION").to_string(),
        cli_path: std::env::current_exe().ok(),
        node_path,
        node_version,
        cli_on_path: crate::commands::setup::which_on_path(if cfg!(windows) { "tenzro.exe" } else { "tenzro" }),
        glibc: glibc_version(),
        node_build,
        gpus: hw.gpus.iter().map(|g| g.name.clone()).collect(),
        config_exists: crate::config::config_path().exists(),
        endpoint,
        endpoint_source: src.describe(),
        net: Some(net),
        local_node: Some(local),
        disk_free_gb: hw.storage_available_gb,
        data_dir: tenzro_types::paths::default_data_dir(),
    };
    (obs, facts)
}

impl DoctorCmd {
    pub async fn execute(self) -> Result<()> {
        let (obs, facts) = gather().await;
        let checks = evaluate(&obs, &facts);
        let failed = checks.iter().filter(|c| c.level == Level::Fail).count();
        if self.json {
            println!("{}", serde_json::to_string_pretty(&to_json(&obs, &checks))?);
        } else {
            println!("Tenzro doctor\n");
            for ch in &checks {
                let (word, col) = match ch.level {
                    Level::Pass => ("ok", colors::ok()),
                    Level::Warn | Level::Todo => ("note", colors::warn()),
                    Level::Fail => ("FAIL", colors::bad()),
                };
                println!("  {col}{word:<5}{}  {:<20} {}", colors::reset(), ch.label, ch.detail);
                if ch.level != Level::Pass {
                    for l in &ch.fix {
                        println!("         fix: {l}");
                    }
                }
            }
            println!();
            if failed == 0 {
                println!("Nothing here blocks Tenzro.");
            } else {
                println!("{failed} check(s) failed. Fix those first.");
            }
        }
        if failed > 0 {
            std::process::exit(1);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::detect::{Net, NodeBuild};

    fn facts() -> Facts {
        Facts {
            root: preflight::Root::Tpm,
            secure_enclave: false,
            tpm_device: false,
            tpm_open_error: None,
            user: "u".into(),
            groups: vec![],
            missing_tools: vec![],
            node_binary: None,
            keys_provisioned: None,
        }
    }

    fn obs() -> Observed {
        Observed {
            cli_version: "0.2.1".into(),
            cli_path: Some("/usr/bin/tenzro".into()),
            node_path: Some("/usr/bin/tenzro-node".into()),
            node_version: Some("tenzro-node 0.2.0".into()),
            cli_on_path: Some("/usr/bin/tenzro".into()),
            glibc: Some("2.39".into()),
            node_build: Some(NodeBuild { flavour: "cpu".into(), startup_ok: true, refusal: None }),
            config_exists: true,
            endpoint: "http://127.0.0.1:8545".into(),
            endpoint_source: "default (this machine)",
            net: Some(Net::NotResolving),
            local_node: Some(false),
            disk_free_gb: 100.0,
            ..Observed::default()
        }
    }

    #[test]
    fn version_lines_compare_major_and_minor_only() {
        assert_eq!(major_minor("tenzro-node 0.2.1"), Some((0, 2)));
        assert_eq!(major_minor("0.2.0"), Some((0, 2)));
        assert_eq!(major_minor("nothing"), None);
        let r = evaluate(&obs(), &facts());
        assert_eq!(r.iter().find(|x| x.label == "tenzro-node").unwrap().level, Level::Pass);
        let mut o = obs();
        o.node_version = Some("tenzro-node 0.3.0".into());
        assert_eq!(evaluate(&o, &facts()).iter().find(|x| x.label == "tenzro-node").unwrap().level, Level::Warn);
    }

    #[test]
    fn every_failing_or_noted_line_carries_a_fix_where_one_exists() {
        let mut o = obs();
        o.node_path = None;
        o.node_build = Some(NodeBuild { flavour: "cpu".into(), startup_ok: false, refusal: Some("GPU present".into()) });
        let r = evaluate(&o, &facts());
        for ch in r.iter().filter(|c| c.level == Level::Fail) {
            assert!(!ch.fix.is_empty(), "{} has no fix", ch.label);
        }
        assert!(r.iter().any(|c| c.label == "TPM 2.0" && c.level == Level::Fail));
    }

    #[test]
    fn the_public_endpoint_not_resolving_points_at_the_local_chain() {
        let r = evaluate(&obs(), &facts());
        let e = r.iter().find(|c| c.label == "Endpoint").unwrap();
        assert!(e.fix.iter().any(|l| l.contains("tenzro dev")));
    }

    #[test]
    fn json_counts_the_failures() {
        let o = obs();
        let r = evaluate(&o, &facts());
        let j = to_json(&o, &r);
        assert_eq!(j["version"], "0.2.1");
        assert!(j["failed"].as_u64().unwrap() >= 1);
    }
}
