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
use crate::commands::stake_options::{LineKind, StakeNeed};
use crate::commands::update::manifest::Version;
use crate::onboarding::message::MsgEnv;
use crate::onboarding::state::ApplicationState;
use crate::output::colors;
use tenzro_onboarding_types::update_state::{self, UpdateRecord, UpdateState};

/// Check this machine and the network, and say how to fix what is wrong
#[derive(Debug, Parser)]
pub struct DoctorCmd {
    /// Print one JSON object for support instead of the checklist.
    #[arg(long)]
    json: bool,
}

/// What `gather` read about software updates.
#[derive(Debug, Clone, Default)]
pub struct UpdateObserved {
    pub record: UpdateRecord,
    /// Why the update state could not be read.
    pub record_error: Option<String>,
    /// A binary is staged for a consensus upgrade and is not the node binary here.
    pub staged: Option<PathBuf>,
    /// SHA-256 of the installed `tenzro-node`.
    pub node_digest: Option<String>,
    /// The state a node running that file advertises.
    pub node_state: Option<UpdateState>,
    /// The `update` object of the running local node's status, when one answers.
    pub live_advert: Option<serde_json::Value>,
    /// The newest verified release notice, from the cache or the local node.
    pub notice: Option<tenzro_update_notice::Notice>,
    /// Where the local node is in its epoch, when it answered.
    pub epoch: Option<tenzro_update_notice::banner::EpochView>,
}

/// The stake this machine's role needs against its wallet, and where the
/// application stands. Rendered through the same builder as `tenzro join`,
/// `tenzro setup` and `tenzro stake bond`.
#[derive(Debug, Clone)]
pub struct StakeCheck {
    pub need: StakeNeed,
    pub state: ApplicationState,
    pub env: MsgEnv,
}

/// What `gather` read.
#[derive(Debug, Clone, Default)]
pub struct Observed {
    pub update: UpdateObserved,
    /// `None` when this machine has no staked role to check.
    pub stake: Option<StakeCheck>,
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
    /// The ladder's verdict on the volume that holds the data directory,
    /// when it could be measured.
    pub disk: Option<tenzro_storage::resources::Assessment>,
    /// The running node's own disk summary line, when a node answered.
    pub node_disk: Option<String>,
}

/// The `major.minor` of a version string such as `tenzro-node 0.2.1`.
pub fn major_minor(s: &str) -> Option<(u32, u32)> {
    let v = s
        .split_whitespace()
        .find(|w| w.chars().next().is_some_and(|c| c.is_ascii_digit()))?;
    let mut it = v.split('.');
    Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
}

fn c(label: &'static str, level: Level, detail: impl Into<String>, fix: &[&str]) -> Check {
    Check {
        label,
        level,
        detail: detail.into(),
        fix: fix.iter().map(|s| s.to_string()).collect(),
    }
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
            o.cli_path
                .as_ref()
                .map_or("?".into(), |p| p.display().to_string())
        ),
        &[],
    ));
    v.push(match (&o.cli_on_path, &o.cli_path) {
        (None, _) => c(
            "On PATH",
            Level::Warn,
            "tenzro is not on PATH",
            &["Open a new terminal after installing, or add its folder to PATH."],
        ),
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
            c(
                "glibc",
                Level::Warn,
                format!("{g}: the release builds need 2.39 or newer"),
                &["Use Ubuntu 24.04 or newer, Debian 13 or newer, or Fedora 40 or newer."],
            )
        });
    }
    v.push(match &o.node_build {
        Some(b) if b.startup_ok => c(
            "Build and graphics",
            Level::Pass,
            format!(
                "{} build; {}",
                b.flavour,
                if o.gpus.is_empty() {
                    "no GPU".to_string()
                } else {
                    o.gpus.join(", ")
                }
            ),
            &[],
        ),
        Some(b) => c(
            "Build and graphics",
            Level::Fail,
            format!(
                "this {} build would refuse to start here: {}",
                b.flavour,
                b.refusal.clone().unwrap_or_default()
            ),
            &["Install the CUDA package on an NVIDIA GPU machine, the CPU package otherwise."],
        ),
        None => c(
            "Build and graphics",
            Level::Warn,
            "tenzro-node did not answer its hardware check",
            &[],
        ),
    });
    v.push(if o.config_exists {
        c(
            "Settings",
            Level::Pass,
            crate::config::config_path().display().to_string(),
            &[],
        )
    } else {
        c(
            "Settings",
            Level::Warn,
            "no settings file yet: this machine is not set up",
            &["Run: tenzro"],
        )
    });
    v.push(match &o.net {
        Some(Net::Reachable { chain_id }) => c(
            "Endpoint",
            Level::Pass,
            format!(
                "{} ({}) answers, chain {chain_id}",
                o.endpoint, o.endpoint_source
            ),
            &[],
        ),
        Some(Net::NotResolving) => c(
            "Endpoint",
            Level::Warn,
            format!(
                "{} ({}): the name does not resolve",
                o.endpoint, o.endpoint_source
            ),
            &[
                "If this is the public network, it is not reachable yet.",
                "Try Tenzro on this machine: tenzro dev",
            ],
        ),
        Some(Net::NotAnswering { reason }) => c(
            "Endpoint",
            Level::Warn,
            format!(
                "{} ({}) did not answer: {reason}",
                o.endpoint, o.endpoint_source
            ),
            &["Check the address and this machine's connection, or try: tenzro dev"],
        ),
        _ => c(
            "Endpoint",
            Level::Warn,
            format!("{} not checked", o.endpoint),
            &[],
        ),
    });
    if let Some(sc) = &o.stake {
        v.push(stake_check(sc));
    }
    v.push(match o.local_node {
        Some(true) => c(
            "Local node",
            Level::Pass,
            "a node answers on this machine",
            &[],
        ),
        Some(false) => c(
            "Local node",
            Level::Pass,
            "no node is running here (only needed to provide or validate)",
            &[],
        ),
        None => c("Local node", Level::Warn, "not checked", &[]),
    });
    v.extend(update_checks(o));
    v.extend(disk_checks(o));
    v
}

/// The disk rows: the ladder's level with the runway and the class given up
/// next, and the running node's own line when it answered. Without a
/// measurement the free figure alone is judged. Pure.
pub fn disk_checks(o: &Observed) -> Vec<Check> {
    use tenzro_storage::resources::Level as Rung;
    let mut v = Vec::new();
    match &o.disk {
        Some(a) => {
            let level = match a.level {
                Rung::Ok => Level::Pass,
                Rung::Warn => Level::Warn,
                _ => Level::Fail,
            };
            let fix: &[&str] = if level == Level::Pass {
                &[]
            } else {
                &[
                    "Free space on the volume, or move the data with --data-dir on a bigger disk.",
                    "Never delete files inside the node's data directory by hand: the node gives up its least valuable data first, and a deleted chain file stops it.",
                ]
            };
            v.push(c("Disk space", level, a.summary(), fix));
        }
        None => {
            v.push(if o.disk_free_gb >= 20.0 || o.disk_free_gb == 0.0 {
                c(
                    "Disk space",
                    Level::Pass,
                    format!("{:.0} GB free", o.disk_free_gb),
                    &[],
                )
            } else {
                c(
                    "Disk space",
                    Level::Warn,
                    format!("{:.0} GB free at {}", o.disk_free_gb, o.data_dir.display()),
                    &["Free some space, or use --data-dir on a bigger disk."],
                )
            });
        }
    }
    if let Some(line) = &o.node_disk {
        v.push(c("Node disk", Level::Pass, line.clone(), &[]));
    }
    v
}

/// The update rows: whether a check was ever run, how far behind this binary is,
/// whether a staged update waits, and what the node advertises. Pure.
pub fn update_checks(o: &Observed) -> Vec<Check> {
    update_checks_for_os(o, std::env::consts::OS)
}

/// [`update_checks`] for the operating system named `os`: where the running
/// program cannot be replaced, the advice is the MSI, not `tenzro update`.
pub fn update_checks_for_os(o: &Observed, os: &str) -> Vec<Check> {
    let hint = |lead: &str| tenzro_update_notice::banner::install_hint(os, lead);
    let lower_first = |t: &str| {
        let mut ch = t.chars();
        ch.next()
            .map(|f| f.to_lowercase().chain(ch).collect::<String>())
            .unwrap_or_default()
    };
    let u = &o.update;
    let mut v = Vec::new();
    if let Some(e) = &u.record_error {
        v.push(c(
            "Update check",
            Level::Warn,
            format!("the update state could not be read: {e}"),
            &["Delete the damaged file, then run: tenzro update check"],
        ));
    } else {
        v.push(match (&u.record.last_check, o.cli_version.parse::<Version>()) {
            (None, _) => c(
                "Update check",
                Level::Warn,
                "no update check has ever been run on this machine",
                &["Run: tenzro update check"],
            ),
            (Some(last), Ok(running)) => match last.release.parse::<Version>() {
                Ok(latest) if running.releases_behind(&latest) > 1 => c(
                    "Update check",
                    Level::Warn,
                    format!("tenzro {running} is more than one release behind {latest}, the newest release the last update check saw"),
                    &[hint("Run").as_str()],
                ),
                Ok(latest) if running.releases_behind(&latest) == 1 => {
                    c("Update check", Level::Pass, format!("tenzro {running} is one release behind {latest}; {}", lower_first(&hint("install it with"))), &[])
                }
                _ => c("Update check", Level::Pass, format!("tenzro {} is current as of the last update check", o.cli_version), &[]),
            },
            (Some(_), Err(_)) => c("Update check", Level::Warn, format!("tenzro {} is not a release version", o.cli_version), &[]),
        });
    }
    if let (Some(n), Ok(running)) = (
        &u.notice,
        o.cli_version.parse::<tenzro_update_notice::Version>(),
    ) && let Some(line) = tenzro_update_notice::banner::line_for_os(n, running, u.epoch, os)
    {
        let mut fix = vec![hint("Run")];
        if !n.notes_url.is_empty() {
            fix.push(format!("Release notes: {}", n.notes_url));
        }
        v.push(Check {
            label: "Release notice",
            level: Level::Warn,
            detail: line,
            fix,
        });
    }
    if let Some(p) = &u.staged {
        v.push(c(
            "Staged update",
            Level::Warn,
            format!("a binary is staged at {} and has not been applied: the node binary here is a different one", p.display()),
            &[
                "Restart the node onto the staged binary when the upgrade is scheduled, or delete the staged file.",
                &hint("A C0 release from the channel is installed with"),
            ],
        ));
    }
    let advert = match (&u.live_advert, &u.node_digest, u.node_state) {
        (Some(a), _, _) => {
            let f = |k: &str| a[k].as_str().unwrap_or("unknown").to_string();
            Some(format!(
                "running node states: version {}, binary {}, state {}",
                f("binary_version"),
                short(&f("platform_digest")),
                f("state")
            ))
        }
        (None, Some(d), Some(st)) => Some(format!(
            "installed {} would state: binary {}, state {}",
            o.node_version.as_deref().unwrap_or("?"),
            short(d),
            st.as_str()
        )),
        _ => None,
    };
    if let Some(detail) = advert {
        v.push(c("Software advert", Level::Pass, detail, &[]));
    }
    v
}

fn short(digest: &str) -> String {
    digest.chars().take(12).collect()
}

/// The stake line. When the wallet is short in the initial phase this is the
/// same text `tenzro join` prints (`StakeNeed::lines_with` -> `stake_gap`):
/// its heading is the detail, the rest are the fix lines.
pub fn stake_check(sc: &StakeCheck) -> Check {
    use crate::rpc::format_tnzo;
    let role = sc.need.role.as_str();
    if sc.state.stake_in_place() {
        return c(
            "Stake",
            Level::Pass,
            format!("the {role} stake is bonded"),
            &[],
        );
    }
    if sc.need.is_met() {
        return c(
            "Stake",
            Level::Pass,
            format!(
                "wallet holds {}, enough for the {role} role ({})",
                format_tnzo(sc.need.balance_wei.unwrap_or(0)),
                format_tnzo(sc.need.required_wei)
            ),
            &[],
        );
    }
    let lines = sc.need.lines_with(&sc.env, sc.state);
    let detail = lines
        .iter()
        .find(|(k, _)| *k == LineKind::Heading)
        .map(|(_, t)| t.clone())
        .unwrap_or_default();
    let fix = lines
        .iter()
        .filter(|(k, _)| *k != LineKind::Heading)
        .map(|(_, t)| t.clone())
        .collect();
    Check {
        label: "Stake",
        level: Level::Warn,
        detail,
        fix,
    }
}

/// Which staked role and wallet this machine is about, from the CLI config.
/// A role waiting on stake (`pending_stake`) wins; otherwise the configured
/// role with the largest stake minimum.
fn stake_target(cfg: &crate::config::PersistedConfig) -> Option<(String, u128, String)> {
    use crate::onboarding::role::JoinRole;
    if let Some(p) = &cfg.pending_stake {
        return Some((
            p.role.clone(),
            p.required_wei.parse().ok()?,
            p.account.clone(),
        ));
    }
    let account = cfg.wallet_address.clone()?;
    let role = cfg
        .roles
        .as_deref()?
        .split(',')
        .filter_map(JoinRole::parse)
        .max_by_key(|r| r.stake_minimum_wei())?;
    Some((role.label().to_string(), role.stake_minimum_wei(), account))
}

async fn gather_stake(endpoint: &str) -> Option<StakeCheck> {
    use crate::onboarding::{flow, phase::Phase, role::JoinRole};
    let cfg = crate::config::load_config();
    let (role_label, required_wei, account) = stake_target(&cfg)?;
    let role = JoinRole::parse(&role_label);
    let key = role.map_or(role_label.clone(), |r| r.slug().to_string());
    let env = MsgEnv::current();
    let rpc = crate::rpc::RpcClient::new(endpoint);
    let (balance_wei, state) = if env.phase == Phase::Foundation {
        let snap = flow::snapshot(
            &rpc,
            &flow::AnySource::from_env(),
            &key,
            role,
            &account,
            required_wei,
        )
        .await;
        (snap.balance_wei, snap.state)
    } else {
        let chain = flow::read_chain(&rpc, &account, role, required_wei).await;
        (
            chain.balance_wei,
            if chain.staked == Some(true) {
                ApplicationState::Staked
            } else {
                ApplicationState::NotApplied
            },
        )
    };
    Some(StakeCheck {
        need: StakeNeed {
            role: role_label,
            required_wei,
            balance_wei,
            account,
        },
        state,
        env,
    })
}

/// The ladder's verdict on the volume under `dir`; `None` when the volume
/// cannot be measured.
fn disk_assessment(dir: &std::path::Path) -> Option<tenzro_storage::resources::Assessment> {
    use tenzro_storage::resources::{Ladder, LadderConfig, Reading, volume_of};
    let volume = volume_of(dir).ok()?;
    Some(Ladder::new(LadderConfig::default()).assess(&Reading::of_volume(volume)))
}

/// The summary line the local node reports for its own disk.
async fn node_disk_line() -> Option<String> {
    let rpc = crate::rpc::RpcClient::new(crate::endpoint::LOCAL_RPC);
    let status: serde_json::Value = rpc
        .call("tenzro_getNodeStatus", serde_json::json!([]))
        .await
        .ok()?;
    status["disk"]["assessment"]["summary"]
        .as_str()
        .map(str::to_string)
}

/// The verdict as JSON, for support.
pub fn to_json(o: &Observed, checks: &[Check]) -> serde_json::Value {
    json!({
        "version": o.cli_version,
        "endpoint": o.endpoint,
        "endpoint_source": o.endpoint_source,
        "failed": checks.iter().filter(|c| c.level == Level::Fail).count(),
        "update": tenzro_update_notice::banner::json_fields(
            o.update.notice.as_ref(),
            o.cli_version.parse().unwrap_or(tenzro_update_notice::Version(0, 0, 0)),
        ),
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
    let out = std::process::Command::new("ldd")
        .arg("--version")
        .output()
        .ok()?;
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()?
        .to_string();
    first.split_whitespace().last().map(str::to_string)
}

async fn observe_updates(
    node_path: Option<PathBuf>,
    local_node: bool,
    data_dir: PathBuf,
) -> UpdateObserved {
    let (record, record_error) = match update_state::load(&data_dir) {
        Ok(r) => (r, None),
        Err(e) => (UpdateRecord::default(), Some(e.to_string())),
    };
    let dir = data_dir.clone();
    let (node_digest, node_state, staged) = tokio::task::spawn_blocking(move || {
        let digest = node_path.and_then(|p| update_state::file_sha256(&p).ok());
        let state = digest
            .as_deref()
            .map(|d| update_state::current_state(&dir, d));
        let staged = update_state::staged_binary_path(&dir);
        let differs = staged.is_file()
            && digest
                .as_deref()
                .is_none_or(|d| update_state::staged_binary_differs(&dir, d));
        (digest, state, differs.then_some(staged))
    })
    .await
    .unwrap_or((None, None, None));
    let live_advert = if local_node {
        crate::rpc::RpcClient::new(crate::endpoint::LOCAL_RPC)
            .call::<serde_json::Value>("tenzro_getNodeStatus", serde_json::json!([]))
            .await
            .ok()
            .map(|st| st["update"].clone())
            .filter(|u| u.is_object())
    } else {
        None
    };
    let now = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let (notice, epoch) = if local_node {
        let got =
            crate::commands::update::notice::from_node(&data_dir, crate::endpoint::LOCAL_RPC, now)
                .await;
        (got.notice, got.epoch)
    } else {
        (
            crate::commands::update::notice::cached(&data_dir, now),
            None,
        )
    };
    UpdateObserved {
        record,
        record_error,
        staged,
        node_digest,
        node_state,
        live_advert,
        notice,
        epoch,
    }
}

async fn gather() -> (Observed, Facts) {
    let hw = crate::commands::hardware::detect_hardware_profile().await;
    let se = crate::commands::setup::has_secure_enclave(&hw);
    let facts = tokio::task::spawn_blocking(move || Facts::probe(se))
        .await
        .unwrap_or_else(|_| Facts::probe(se));
    let node_path = facts.node_binary.clone();
    let node_version = node_path.clone().and_then(|p| {
        let out = std::process::Command::new(p)
            .arg("--version")
            .output()
            .ok()?;
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    });
    let node_build = match node_path.clone() {
        Some(p) => tokio::task::spawn_blocking(move || {
            let out = std::process::Command::new(p)
                .arg("hardware")
                .output()
                .ok()?;
            crate::tui::detect::parse_node_hardware(&String::from_utf8_lossy(&out.stdout))
        })
        .await
        .ok()
        .flatten(),
        None => None,
    };
    let (endpoint, src) = crate::endpoint::resolve();
    let net = crate::tui::detect::check_network(&endpoint).await;
    let local = crate::tui::detect::check_network(crate::endpoint::LOCAL_RPC)
        .await
        .is_reachable();
    let update = observe_updates(
        node_path.clone(),
        local,
        tenzro_types::paths::default_data_dir(),
    )
    .await;
    let stake = gather_stake(&endpoint).await;
    let obs = Observed {
        update,
        stake,
        cli_version: env!("CARGO_PKG_VERSION").to_string(),
        cli_path: std::env::current_exe().ok(),
        node_path,
        node_version,
        cli_on_path: crate::commands::setup::which_on_path(if cfg!(windows) {
            "tenzro.exe"
        } else {
            "tenzro"
        }),
        glibc: glibc_version(),
        node_build,
        gpus: hw.gpus.iter().map(|g| g.name.clone()).collect(),
        config_exists: crate::config::config_path().exists(),
        endpoint,
        endpoint_source: src.describe(),
        net: Some(net),
        local_node: Some(local),
        disk_free_gb: hw.storage_available_gb,
        disk: disk_assessment(&tenzro_types::paths::default_data_dir()),
        node_disk: if local { node_disk_line().await } else { None },
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
                println!(
                    "  {col}{word:<5}{}  {:<20} {}",
                    colors::reset(),
                    ch.label,
                    ch.detail
                );
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
                let next = checks
                    .iter()
                    .find(|c| c.level == Level::Fail)
                    .and_then(|c| c.fix.first());
                match next {
                    Some(f) => println!("{failed} check(s) failed. Next: {f}"),
                    None => println!("{failed} check(s) failed. Fix those first."),
                }
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
            node_build: Some(NodeBuild {
                flavour: "cpu".into(),
                startup_ok: true,
                refusal: None,
            }),
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
        assert_eq!(
            r.iter().find(|x| x.label == "tenzro-node").unwrap().level,
            Level::Pass
        );
        let mut o = obs();
        o.node_version = Some("tenzro-node 0.3.0".into());
        assert_eq!(
            evaluate(&o, &facts())
                .iter()
                .find(|x| x.label == "tenzro-node")
                .unwrap()
                .level,
            Level::Warn
        );
    }

    #[test]
    fn every_failing_or_noted_line_carries_a_fix_where_one_exists() {
        let mut o = obs();
        o.node_path = None;
        o.node_build = Some(NodeBuild {
            flavour: "cpu".into(),
            startup_ok: false,
            refusal: Some("GPU present".into()),
        });
        let r = evaluate(&o, &facts());
        for ch in r.iter().filter(|c| c.level == Level::Fail) {
            assert!(!ch.fix.is_empty(), "{} has no fix", ch.label);
        }
        assert!(
            r.iter()
                .any(|c| c.label == "TPM 2.0" && c.level == Level::Fail)
        );
    }

    #[test]
    fn the_public_endpoint_not_resolving_points_at_the_local_chain() {
        let r = evaluate(&obs(), &facts());
        let e = r.iter().find(|c| c.label == "Endpoint").unwrap();
        assert!(e.fix.iter().any(|l| l.contains("tenzro dev")));
    }

    fn stake_obs(
        state: ApplicationState,
        phase: crate::onboarding::phase::Phase,
        balance: Option<u128>,
    ) -> Observed {
        let mut o = obs();
        o.stake = Some(StakeCheck {
            need: StakeNeed {
                role: "validator".into(),
                required_wei: 10_000 * 1_000_000_000_000_000_000,
                balance_wei: balance,
                account: format!("0x{}", "ab".repeat(32)),
            },
            state,
            env: MsgEnv::with_phase(phase),
        });
        o
    }

    #[test]
    fn doctor_uses_the_same_words_as_join() {
        use crate::onboarding::message::{GapInput, stake_gap};
        use crate::onboarding::phase::Phase;
        let o = stake_obs(ApplicationState::Approved, Phase::Foundation, Some(0));
        let r = evaluate(&o, &facts());
        let ch = r.iter().find(|c| c.label == "Stake").unwrap();
        assert_eq!(
            ch.level,
            Level::Warn,
            "a missing stake is a note, not a failure"
        );
        let sc = o.stake.as_ref().unwrap();
        let direct = stake_gap(
            &GapInput {
                role_label: "validator",
                required_wei: sc.need.required_wei,
                balance_wei: Some(0),
                account: &sc.need.account,
                state: sc.state,
            },
            &sc.env,
        )
        .unwrap();
        assert_eq!(ch.detail, direct[0].1);
        assert_eq!(
            ch.fix,
            direct[1..]
                .iter()
                .map(|(_, t)| t.clone())
                .collect::<Vec<_>>()
        );
        assert!(ch.detail.contains("10000 TNZO"));
    }

    #[test]
    fn doctor_stake_note_goes_away_in_open_stake_phase_wording() {
        use crate::onboarding::phase::Phase;
        let o = stake_obs(ApplicationState::NotApplied, Phase::OpenStake, Some(0));
        let ch = evaluate(&o, &facts())
            .into_iter()
            .find(|c| c.label == "Stake")
            .unwrap();
        assert!(
            !ch.fix
                .iter()
                .any(|l| l.contains("How to apply") || l.contains("PLACEHOLDER")),
            "{:?}",
            ch.fix
        );
    }

    #[test]
    fn doctor_stake_is_ok_when_funded_or_bonded_and_absent_without_a_role() {
        use crate::onboarding::phase::Phase;
        let one = 1_000_000_000_000_000_000u128;
        let funded = evaluate(
            &stake_obs(
                ApplicationState::Funded,
                Phase::Foundation,
                Some(10_000 * one),
            ),
            &facts(),
        );
        assert_eq!(
            funded.iter().find(|c| c.label == "Stake").unwrap().level,
            Level::Pass
        );
        let bonded = evaluate(
            &stake_obs(ApplicationState::Staked, Phase::Foundation, Some(0)),
            &facts(),
        );
        assert_eq!(
            bonded.iter().find(|c| c.label == "Stake").unwrap().level,
            Level::Pass
        );
        assert!(
            evaluate(&obs(), &facts())
                .iter()
                .all(|c| c.label != "Stake")
        );
    }

    #[test]
    fn doctor_stake_note_leaks_no_raw_error_when_balance_is_unreadable() {
        use crate::onboarding::phase::Phase;
        let ch = evaluate(
            &stake_obs(ApplicationState::NotApplied, Phase::Foundation, None),
            &facts(),
        )
        .into_iter()
        .find(|c| c.label == "Stake")
        .unwrap();
        assert!(ch.detail.contains("could not be checked"), "{}", ch.detail);
    }

    #[test]
    fn json_counts_the_failures() {
        let o = obs();
        let r = evaluate(&o, &facts());
        let j = to_json(&o, &r);
        assert_eq!(j["version"], "0.2.1");
        assert!(j["failed"].as_u64().unwrap() >= 1);
    }

    fn update_row(o: &Observed, label: &str) -> Option<Check> {
        update_checks_for_os(o, "linux")
            .into_iter()
            .find(|c| c.label == label)
    }

    fn checked(release: &str) -> UpdateObserved {
        UpdateObserved {
            record: UpdateRecord {
                last_check: Some(update_state::LastCheck {
                    checked_ms: 1,
                    release: release.into(),
                    manifest_version: 9,
                }),
                ..UpdateRecord::default()
            },
            ..UpdateObserved::default()
        }
    }

    #[test]
    fn doctor_warns_when_no_update_check_was_ever_run() {
        let r = evaluate(&obs(), &facts());
        let u = r.iter().find(|c| c.label == "Update check").unwrap();
        assert_eq!(u.level, Level::Warn);
        assert_eq!(
            u.detail,
            "no update check has ever been run on this machine"
        );
        assert_eq!(u.fix, vec!["Run: tenzro update check".to_string()]);
    }

    #[test]
    fn doctor_never_tells_a_windows_operator_to_run_tenzro_update() {
        let mut o = obs();
        for last in ["0.2.4", "0.2.2"] {
            o.update = checked(last);
            let rows = update_checks_for_os(&o, "windows");
            for row in rows {
                assert!(
                    !row.detail.contains("tenzro update")
                        || row.detail.contains("tenzro update check"),
                    "{}",
                    row.detail
                );
                for f in &row.fix {
                    assert!(
                        !f.contains("tenzro update") || f.contains("tenzro update check"),
                        "{f}"
                    );
                }
            }
        }
        o.update = checked("0.2.4");
        let u = update_checks_for_os(&o, "windows")
            .into_iter()
            .find(|c| c.label == "Update check")
            .unwrap();
        assert_eq!(
            u.fix,
            vec!["Install the new release with its MSI".to_string()]
        );
    }

    #[test]
    fn doctor_warns_when_more_than_one_release_behind() {
        let mut o = obs();
        o.update = checked("0.2.4");
        let u = update_row(&o, "Update check").unwrap();
        assert_eq!(u.level, Level::Warn);
        assert_eq!(
            u.detail,
            "tenzro 0.2.1 is more than one release behind 0.2.4, the newest release the last update check saw"
        );
        assert_eq!(u.fix, vec!["Run: tenzro update".to_string()]);
        // Crossing a minor line is also more than one release.
        o.update = checked("0.3.0");
        assert_eq!(update_row(&o, "Update check").unwrap().level, Level::Warn);
    }

    #[test]
    fn doctor_does_not_warn_when_current_or_one_release_behind() {
        let mut o = obs();
        o.update = checked("0.2.1");
        let u = update_row(&o, "Update check").unwrap();
        assert_eq!(u.level, Level::Pass);
        assert_eq!(
            u.detail,
            "tenzro 0.2.1 is current as of the last update check"
        );
        o.update = checked("0.2.2");
        let u = update_row(&o, "Update check").unwrap();
        assert_eq!(u.level, Level::Pass);
        assert!(u.detail.contains("one release behind 0.2.2"));
    }

    #[test]
    fn doctor_warns_about_a_staged_update_that_was_not_applied() {
        let mut o = obs();
        assert!(update_row(&o, "Staged update").is_none());
        o.update.staged = Some("/var/lib/tenzro/upgrade/staged".into());
        let u = update_row(&o, "Staged update").unwrap();
        assert_eq!(u.level, Level::Warn);
        assert_eq!(
            u.detail,
            "a binary is staged at /var/lib/tenzro/upgrade/staged and has not been applied: the node binary here is a different one"
        );
    }

    #[test]
    fn doctor_shows_what_the_node_advertises_and_says_so_plainly_when_the_state_is_unreadable() {
        let mut o = obs();
        o.node_version = Some("tenzro-node 0.2.0".into());
        o.update.node_digest = Some("ab".repeat(32));
        o.update.node_state = Some(UpdateState::Staged);
        let a = update_row(&o, "Software advert").unwrap();
        assert_eq!(
            a.detail,
            "installed tenzro-node 0.2.0 would state: binary abababababab, state staged"
        );
        o.update.live_advert = Some(
            json!({ "binary_version": "0.2.0", "platform_digest": "cd".repeat(32), "state": "running" }),
        );
        let a = update_row(&o, "Software advert").unwrap();
        assert_eq!(
            a.detail,
            "running node states: version 0.2.0, binary cdcdcdcdcdcd, state running"
        );
        o.update.record_error = Some("state.json: bad".into());
        let u = update_row(&o, "Update check").unwrap();
        assert!(u.detail.starts_with("the update state could not be read"));
    }

    #[test]
    fn doctor_shows_the_ladder_with_runway_and_names_what_to_free() {
        use tenzro_storage::resources::{GIB, Ladder, LadderConfig, Reading, VolumeStats};
        let mut o = observed_for_disk();
        let reading = Reading {
            volume: VolumeStats::of(100 * GIB, 11 * GIB),
            host: Default::default(),
            bytes_per_block: Some(230_000.0),
        };
        o.disk = Some(Ladder::new(LadderConfig::default()).assess(&reading));
        let checks = disk_checks(&o);
        let row = checks.iter().find(|c| c.label == "Disk space").unwrap();
        assert_eq!(row.level, Level::Fail);
        assert!(row.detail.contains("runway") && row.detail.contains("next sacrificed"));
        assert!(
            row.fix.iter().any(|l| l.contains("Never delete")),
            "{:?}",
            row.fix
        );
        assert!(
            checks.iter().all(|c| c.label != "Node disk"),
            "no node answered"
        );
    }

    #[test]
    fn doctor_passes_a_roomy_volume_and_falls_back_to_the_old_figure_without_a_measurement() {
        use tenzro_storage::resources::{GIB, Ladder, LadderConfig, Reading, VolumeStats};
        let mut o = observed_for_disk();
        let reading = Reading::of_volume(VolumeStats::of(1000 * GIB, 800 * GIB));
        o.disk = Some(Ladder::new(LadderConfig::default()).assess(&reading));
        assert_eq!(disk_checks(&o)[0].level, Level::Pass);
        o.disk = None;
        o.disk_free_gb = 5.0;
        assert_eq!(disk_checks(&o)[0].level, Level::Warn);
    }

    fn observed_for_disk() -> Observed {
        Observed {
            data_dir: "/var/lib/tenzro".into(),
            ..Observed::default()
        }
    }
}
