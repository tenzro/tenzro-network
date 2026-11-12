//! Bare `tenzro update`: the whole update in one command.
//!
//! It asks the channel, shows what it found, installs a C0 release exactly as
//! `tenzro update apply` does, restarts the node through its installed
//! service, and runs the health gate `tenzro update verify` runs. A release
//! that does not stay healthy is rolled back and the service is restarted
//! once more, so the previous release runs again.
//!
//! The restart is the one step it does not always take. A node that serves a
//! staked role is restarted by its operator, at a moment the epoch allows. A
//! node with no installed service was started by hand and is restarted the
//! same way. In both cases the release is installed and the remaining steps
//! are printed, as `tenzro update apply` prints them.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use clap::Args;
use serde_json::Value;

use super::health::{self, Observation, Reason, Verdict};
use super::install::Layout;
use super::{Availability, ChannelArgs, Ctx, notice};
use crate::commands::service::{self, NodeService};
use crate::output;

/// The options of bare `tenzro update`.
#[derive(Debug, Args)]
pub struct WholeArgs {
    #[command(flatten)]
    args: ChannelArgs,
    /// The install directory: a Tenzro install root (with `versions/` and `current`) or a folder holding the binaries. Defaults to where this `tenzro` runs from.
    #[arg(long)]
    install_dir: Option<PathBuf>,
    /// Install without asking first. Needed when no terminal is attached.
    #[arg(long)]
    yes: bool,
    /// Install only: the restart and `tenzro update verify` are left to you.
    #[arg(long)]
    no_restart: bool,
    /// The node's JSON-RPC endpoint: asked for the node's roles before a restart and for its health after it.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc_url: String,
    /// Seconds between health probes after the restart.
    #[arg(long, default_value_t = 10)]
    interval_secs: u64,
    /// Seconds the new release has, from its first start, to prove itself healthy.
    #[arg(long, default_value_t = health::DEFAULT_WINDOW_MS / 1000)]
    health_window_secs: u64,
    /// Starts the new release may have before it is rolled back.
    #[arg(long, default_value_t = health::DEFAULT_MAX_BOOT_ATTEMPTS)]
    max_boot_attempts: u32,
}

/// What the operator said about installing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consent {
    /// `--yes`: install without asking.
    Given,
    /// A terminal is attached: ask.
    Ask,
    /// No `--yes` and nobody to ask: install nothing.
    Missing,
}

/// Whether to install, ask first, or hold back. Pure.
pub fn consent(yes: bool, stdin_is_terminal: bool) -> Consent {
    match (yes, stdin_is_terminal) {
        (true, _) => Consent::Given,
        (false, true) => Consent::Ask,
        (false, false) => Consent::Missing,
    }
}

/// What is known about the roles of the node on this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// It serves a staked role: a validator or a provider.
    Serves,
    /// It answered and serves no staked role.
    None,
    /// It did not answer, or did not say.
    Unknown,
}

/// Why a release was installed and the node was left as it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Why {
    /// `--no-restart` was given.
    Asked,
    /// The node serves a staked role; its operator picks the moment.
    ServesRole,
    /// This system has no node service that `tenzro setup` installs.
    NoServiceHere,
    /// The node service `tenzro setup` installs is not running on this machine.
    NoService,
    /// The node did not say which roles it serves.
    RoleUnknown,
    /// The installed service starts something other than the node that was
    /// just installed, or what it starts could not be read.
    OtherProgram {
        starts: Option<String>,
        installed: String,
    },
}

impl Why {
    fn says(&self) -> String {
        match self {
            Why::Asked => "--no-restart was given.".into(),
            Why::ServesRole => "this node serves a staked role, so the moment of its restart is yours to choose.".into(),
            Why::NoServiceHere => "`tenzro update` restarts the node service that `tenzro setup` installs, and there is none for this system.".into(),
            Why::NoService => {
                "the node service that `tenzro setup` installs is not running on this machine, so the node is restarted the way it was started.".into()
            }
            Why::RoleUnknown => {
                "the node did not answer, so it is not known whether it serves a staked role. `--rpc-url` names the node to ask.".into()
            }
            Why::OtherProgram { starts: Some(starts), installed } => {
                format!("the installed service starts {starts}, which is not the node just installed. Point the service at {installed}.")
            }
            Why::OtherProgram { starts: None, installed } => {
                format!("what the installed service starts could not be read, so it is not known to be the node just installed ({installed}).")
            }
        }
    }
}

/// What happens after the install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// Restart the node service, then run the health gate.
    Restart,
    /// Install only, and print the steps that remain.
    InstallOnly(Why),
}

/// Decides whether this command restarts the node. `os` is
/// `std::env::consts::OS`. The node is restarted only through the service
/// `tenzro setup` installs, and only when it is known to serve no staked
/// role. Pure.
pub fn plan(os: &str, service: &NodeService, role: Role, no_restart: bool) -> Plan {
    if no_restart {
        return Plan::InstallOnly(Why::Asked);
    }
    if role == Role::Serves {
        return Plan::InstallOnly(Why::ServesRole);
    }
    match (os, service) {
        ("linux", NodeService::Systemd(_)) | ("macos", NodeService::Launchd(_)) => {}
        ("linux" | "macos", _) => return Plan::InstallOnly(Why::NoService),
        _ => return Plan::InstallOnly(Why::NoServiceHere),
    }
    if role == Role::Unknown {
        return Plan::InstallOnly(Why::RoleUnknown);
    }
    Plan::Restart
}

/// The roles a node reports in `tenzro_getNodeStatus`, as a [`Role`]. Pure.
pub fn role_of(status: &Value) -> Role {
    let roles: Vec<&str> = match status.get("roles") {
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
        Some(Value::String(s)) => s.split(',').map(str::trim).collect(),
        _ => return Role::Unknown,
    };
    if notice::serves_role(roles) {
        Role::Serves
    } else {
        Role::None
    }
}

/// How the command ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The channel offers nothing newer.
    UpToDate,
    /// A newer release exists and is not C0: reported, not installed.
    Held,
    /// A release is available; nothing was installed because nobody could be asked.
    NeedsYes { release: String },
    /// The operator said no.
    Declined,
    /// Installed; the restart is left to the operator.
    Installed(Why),
    /// Installed, restarted and healthy.
    Healthy,
    /// Installed and restarted, then rolled back. `previous_runs` says whether
    /// the second restart, onto the previous release, went through.
    RolledBack { reason: Reason, previous_runs: bool },
}

/// The limits one run works under.
pub struct Opts {
    pub consent: Consent,
    pub policy: health::Policy,
    /// Time between health probes.
    pub interval: Duration,
}

/// What the flow needs from the machine it runs on. The command hands in the
/// real machine; a test hands in a stand-in, so the whole flow runs with no
/// service, no node and no waiting.
pub trait Machine {
    /// The time, in ms.
    fn now(&self) -> u64;
    /// Asks the operator; only called when a terminal is attached.
    fn confirm(&self, question: &str) -> Result<bool>;
    /// What to do after the install. Asked before anything is installed.
    async fn plan(&self) -> Plan;
    /// After the install: `Some` when the service would not start the node
    /// that was just installed.
    fn service_mismatch(&self, layout: &Layout) -> Option<Why>;
    /// The advice for an operator who restarts a node that serves a role.
    async fn restart_advice(&self) -> String;
    /// Restarts the node service.
    fn restart(&self) -> Result<()>;
    /// Waits between two health probes.
    async fn sleep(&self, d: Duration);
    /// One health probe of the running node.
    async fn probe(&self) -> Result<Observation>;
}

/// The whole update: check, install, restart, health gate. Returns how it
/// ended; the caller turns that into the exit status.
pub async fn flow(ctx: &Ctx, layout: &Layout, opts: &Opts, m: &impl Machine) -> Result<Outcome> {
    let release = match super::check_or_explain(ctx, m.now()).await? {
        Availability::UpToDate => {
            super::say_current(ctx);
            if let Ok(Some(t)) = health::load(&ctx.data_dir)
                && t.state == health::TrialState::Pending
            {
                output::print_info(&format!(
                    "Release {} is installed and its health check is still open. After the node restarts, run: tenzro update verify",
                    t.release
                ));
            }
            return Ok(Outcome::UpToDate);
        }
        Availability::Held {
            release,
            class,
            description,
        } => {
            super::say_held(&release, class, &description);
            return Ok(Outcome::Held);
        }
        Availability::Available {
            release,
            manifest_version,
            description,
        } => {
            super::say_available(ctx, &release, manifest_version, &description);
            release
        }
    };

    if opts.consent == Consent::Missing {
        return Ok(Outcome::NeedsYes { release });
    }
    let plan = m.plan().await;
    if opts.consent == Consent::Ask {
        let question = match plan {
            Plan::Restart => format!("Install {release} and restart the node service?"),
            Plan::InstallOnly(_) => format!("Install {release}? The node is not restarted."),
        };
        if !m.confirm(&question)? {
            output::print_info("Nothing was installed.");
            return Ok(Outcome::Declined);
        }
    }

    let applied = super::apply_with(ctx, layout, m.now(), opts.policy).await?;
    // Only now can the service be held against what was installed: the
    // install is what moved `current`.
    let plan = match plan {
        Plan::Restart => m
            .service_mismatch(layout)
            .map_or(Plan::Restart, Plan::InstallOnly),
        install_only => install_only,
    };
    let names = applied.installed.names.join(", ");
    if let Plan::InstallOnly(why) = plan {
        output::print_success(&format!(
            "Installed {} ({names}). Nothing was restarted.",
            applied.release
        ));
        output::print_field("Previous kept at", &applied.installed.previous);
        output::print_info(&format!("The node was not restarted: {}", why.says()));
        if why == Why::ServesRole {
            output::print_info(&m.restart_advice().await);
        }
        super::say_next_steps(&applied.rollback_script);
        return Ok(Outcome::Installed(why));
    }

    output::print_success(&format!("Installed {} ({names}).", applied.release));
    output::print_field("Previous kept at", &applied.installed.previous);
    output::print_info("Restarting the node service onto the new release.");
    if let Err(e) = m.restart() {
        output::print_warning(&format!(
            "{} is installed, but the node service was not restarted: {e:#}",
            applied.release
        ));
        super::say_next_steps(&applied.rollback_script);
        return Err(anyhow!(
            "the node was not restarted onto {}",
            applied.release
        ));
    }

    let verdict = super::gate_with_progress(
        &ctx.data_dir,
        layout,
        opts.interval,
        || m.now(),
        async |d| m.sleep(d).await,
        async || m.probe().await,
    )
    .await?;
    match verdict {
        Verdict::Good => {
            output::print_success(&format!(
                "Tenzro {} is running and healthy, and is marked good.",
                applied.release
            ));
            Ok(Outcome::Healthy)
        }
        Verdict::RolledBack(reason) => {
            output::print_warning(&format!("Rolled back to the previous release: {reason}."));
            // The binaries are the previous release again; the service still
            // runs whatever it last started. One more restart runs them.
            let previous_runs = match m.restart() {
                Ok(()) => {
                    output::print_info(
                        "The node service was restarted and runs the previous release again.",
                    );
                    true
                }
                Err(e) => {
                    output::print_warning(&format!(
                        "The node service was not restarted ({e:#}). Restart the node to run the previous release."
                    ));
                    false
                }
            };
            Ok(Outcome::RolledBack {
                reason,
                previous_runs,
            })
        }
    }
}

/// Whether two paths name the same file once links are followed.
fn same_file(a: &Path, b: &Path) -> bool {
    matches!((a.canonicalize(), b.canonicalize()), (Ok(a), Ok(b)) if a == b)
}

/// `Some` when `starts`, the program the service runs, is not the node at
/// `installed`.
pub fn mismatch(starts: Option<PathBuf>, installed: &Path) -> Option<Why> {
    match starts {
        Some(p) if same_file(&p, installed) => None,
        other => Some(Why::OtherProgram {
            starts: other.map(|p| p.display().to_string()),
            installed: installed.display().to_string(),
        }),
    }
}

/// Asks the node at `rpc_url` which roles it serves.
async fn node_role(rpc_url: &str) -> Role {
    let client = crate::rpc::RpcClient::new(rpc_url);
    let call = client.call::<Value>("tenzro_getNodeStatus", serde_json::json!([]));
    match tokio::time::timeout(Duration::from_secs(3), call).await {
        Ok(Ok(status)) => role_of(&status),
        _ => Role::Unknown,
    }
}

/// The machine this command runs on.
struct Host<'a> {
    cmd: &'a WholeArgs,
    data_dir: PathBuf,
    service: NodeService,
    client: reqwest::Client,
}

impl Machine for Host<'_> {
    fn now(&self) -> u64 {
        super::now_ms()
    }

    fn confirm(&self, question: &str) -> Result<bool> {
        Ok(dialoguer::Confirm::new()
            .with_prompt(question)
            .default(false)
            .interact()?)
    }

    async fn plan(&self) -> Plan {
        // With --no-restart the node's answer changes nothing, so it is not asked.
        let role = if self.cmd.no_restart {
            Role::Unknown
        } else {
            node_role(&self.cmd.rpc_url).await
        };
        plan(
            std::env::consts::OS,
            &self.service,
            role,
            self.cmd.no_restart,
        )
    }

    fn service_mismatch(&self, layout: &Layout) -> Option<Why> {
        mismatch(
            service::program(&self.service),
            &layout.binary("tenzro-node"),
        )
    }

    async fn restart_advice(&self) -> String {
        notice::restart_advice(&self.data_dir, &self.cmd.rpc_url, super::now_ms()).await
    }

    fn restart(&self) -> Result<()> {
        service::restart(&self.service)
    }

    async fn sleep(&self, d: Duration) {
        tokio::time::sleep(d).await
    }

    async fn probe(&self) -> Result<Observation> {
        health::probe_rpc(&self.client, &self.cmd.rpc_url).await
    }
}

impl WholeArgs {
    pub(super) async fn execute(&self) -> Result<()> {
        let ctx = Ctx::from_args(&self.args)?;
        let layout = super::layout_of(&self.install_dir)?;
        // The signed notice first, as `tenzro update check` does: it also
        // reaches a machine that cannot read the channel's manifest.
        let (endpoint, _) = crate::endpoint::resolve();
        let _ = notice::refresh(
            &ctx.data_dir,
            &self.args.channel,
            Some(&endpoint),
            super::now_ms(),
        )
        .await;
        let opts = Opts {
            consent: consent(
                self.yes,
                std::io::IsTerminal::is_terminal(&std::io::stdin()),
            ),
            policy: health::Policy {
                window_ms: self.health_window_secs.saturating_mul(1000),
                max_boot_attempts: self.max_boot_attempts,
                ..health::Policy::default()
            },
            interval: Duration::from_secs(self.interval_secs.max(1)),
        };
        let host = Host {
            cmd: self,
            data_dir: ctx.data_dir.clone(),
            service: service::installed(std::env::consts::OS),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()?,
        };
        match flow(&ctx, &layout, &opts, &host).await? {
            Outcome::NeedsYes { release } => bail!(
                "release {release} was not installed: no terminal is attached to confirm on. To install it, run: tenzro update --yes"
            ),
            Outcome::RolledBack { .. } => bail!("the update failed its health check"),
            Outcome::UpToDate
            | Outcome::Held
            | Outcome::Declined
            | Outcome::Installed(_)
            | Outcome::Healthy => Ok(()),
        }
    }
}
