//! `tenzro update`: check for, install and roll back a signed C0 update.
//!
//! With no step named, `tenzro update` is the whole update in one command:
//! check, install, restart the node service, health gate (module `run`). The
//! steps below are the same work one at a time.
//!
//! C0 is the class of node-local fixes, performance, CLI/UI and non-consensus
//! security fixes. A release that changes consensus or state rules (C1, C2)
//! is reported and never applied here: it needs the coordinated activation
//! path (`tenzro governance upgrade-ready`).
//!
//! `apply` verifies everything before it changes anything in the install
//! directory, and restarts nothing. It installs the new release beside the
//! running one (the inactive slot), repoints `current`, and opens a trial
//! (see [`health`]): the node's starts are counted by `boot-check`, and
//! `verify` confirms the release healthy inside a window or restores the
//! previous one by itself.

pub mod health;
pub mod install;
pub mod manifest;
pub mod notice;
mod run;

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use sha2::{Digest, Sha256};
use tenzro_onboarding_types::update_state::{self, LastCheck, UpdateRecord};

use self::install::Layout;
use self::manifest::{Class, Local, TrustRoot, Verified, Version};
use crate::output;

const DEFAULT_CHANNEL: &str = "https://downloads.tenzro.com/update/stable";

/// Update commands
#[derive(Debug, Subcommand)]
pub enum UpdateCommand {
    /// Ask the release channel whether a newer C0 update exists
    Check(CheckCmd),
    /// Verify a signed C0 update completely, then swap the binaries (restarts nothing)
    Apply(ApplyCmd),
    /// Put the previous binaries back; runs no new binary and needs no network
    Rollback(RollbackCmd),
    /// Show the newest signed release notice this machine holds (--refresh asks the channel or a node)
    Notice(notice::NoticeCmd),
    /// Turn release banners on or off
    Notices(notice::NoticesCmd),
    /// Count a node start against the open update trial; the node unit runs this before the node
    BootCheck(BootCheckCmd),
    /// Probe the restarted node for the health window; mark the release good or roll it back
    Verify(VerifyCmd),
}

impl UpdateCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Check(c) => c.execute().await,
            Self::Apply(c) => c.execute().await,
            Self::Rollback(c) => c.execute().await,
            Self::Notice(c) => c.execute().await,
            Self::Notices(c) => c.execute(),
            Self::BootCheck(c) => c.execute().await,
            Self::Verify(c) => c.execute().await,
        }
    }
}

/// `tenzro update`, with or without a step.
///
/// With no step it is the whole update. Its options belong to that form only:
/// once a step is named, the step's own options apply and these are refused.
#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct UpdateCmd {
    #[command(subcommand)]
    step: Option<UpdateCommand>,
    #[command(flatten)]
    whole: run::WholeArgs,
}

impl UpdateCmd {
    pub async fn execute(&self) -> Result<()> {
        match &self.step {
            Some(step) => step.execute().await,
            None => self.whole.execute().await,
        }
    }
}

#[derive(Debug, Args)]
struct Where {
    /// Node data directory, where the update state is kept.
    #[arg(long, env = "TENZRO_DATA_DIR")]
    data_dir: Option<PathBuf>,
}

impl Where {
    fn data_dir(&self) -> PathBuf {
        self.data_dir
            .clone()
            .unwrap_or_else(tenzro_types::paths::default_data_dir)
    }
}

#[derive(Debug, Args)]
struct ChannelArgs {
    /// The release channel: an https URL, or a local directory holding timestamp.json, targets.json and the files.
    #[arg(long, env = "TENZRO_UPDATE_CHANNEL", default_value = DEFAULT_CHANNEL)]
    channel: String,
    /// JSON file of trusted keys; default `<data-dir>/update/trusted-keys.json`, else the built-in root.
    #[arg(long)]
    trusted_keys: Option<PathBuf>,
    /// Platform to fetch, `<arch>-<os>`; defaults to this machine's.
    #[arg(long)]
    platform: Option<String>,
    #[command(flatten)]
    at: Where,
}

/// `tenzro update check`
#[derive(Debug, Parser)]
pub struct CheckCmd {
    #[command(flatten)]
    args: ChannelArgs,
}

/// `tenzro update apply`
#[derive(Debug, Parser)]
pub struct ApplyCmd {
    #[command(flatten)]
    args: ChannelArgs,
    /// The install directory: a Tenzro install root (with `versions/` and `current`) or a folder holding the binaries. Defaults to where this `tenzro` runs from.
    #[arg(long)]
    install_dir: Option<PathBuf>,
    /// Seconds the new release has, from its first start, to prove itself healthy.
    #[arg(long, default_value_t = health::DEFAULT_WINDOW_MS / 1000)]
    health_window_secs: u64,
    /// Starts the new release may have before it is rolled back.
    #[arg(long, default_value_t = health::DEFAULT_MAX_BOOT_ATTEMPTS)]
    max_boot_attempts: u32,
}

/// `tenzro update boot-check`
#[derive(Debug, Parser)]
pub struct BootCheckCmd {
    /// The install directory; defaults to where this `tenzro` runs from.
    #[arg(long)]
    install_dir: Option<PathBuf>,
    #[command(flatten)]
    at: Where,
}

/// `tenzro update verify`
#[derive(Debug, Parser)]
pub struct VerifyCmd {
    /// The install directory; defaults to where this `tenzro` runs from.
    #[arg(long)]
    install_dir: Option<PathBuf>,
    /// The node's JSON-RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc_url: String,
    /// Seconds between probes.
    #[arg(long, default_value_t = 10)]
    interval_secs: u64,
    #[command(flatten)]
    at: Where,
}

/// `tenzro update rollback`
#[derive(Debug, Parser)]
pub struct RollbackCmd {
    /// The install directory; defaults to where this `tenzro` runs from.
    #[arg(long)]
    install_dir: Option<PathBuf>,
    #[command(flatten)]
    at: Where,
}

fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

fn this_platform() -> String {
    format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
}

fn running_release() -> Result<Version> {
    env!("CARGO_PKG_VERSION")
        .parse()
        .map_err(|e: String| anyhow!(e))
}

/// Where a channel's files come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Channel {
    Dir(PathBuf),
    Http(String),
}

impl Channel {
    pub fn parse(s: &str) -> Channel {
        if s.starts_with("https://") || s.starts_with("http://") {
            Channel::Http(s.trim_end_matches('/').to_string())
        } else {
            Channel::Dir(PathBuf::from(s.strip_prefix("file://").unwrap_or(s)))
        }
    }

    fn describe(&self) -> String {
        match self {
            Channel::Dir(p) => p.display().to_string(),
            Channel::Http(u) => u.clone(),
        }
    }

    /// A small metadata document, read whole and no larger than `max`.
    async fn small(&self, name: &str, max: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.stream(name, max as u64, &mut |c| {
            out.extend_from_slice(c);
            Ok(())
        })
        .await?;
        Ok(out)
    }

    /// Feeds `name` to `sink` in chunks; stops with an error as soon as more than `max` bytes arrive.
    async fn stream(
        &self,
        name: &str,
        max: u64,
        sink: &mut (dyn FnMut(&[u8]) -> Result<()> + Send),
    ) -> Result<()> {
        let mut seen = 0u64;
        let mut take = |chunk: &[u8]| -> Result<()> {
            seen += chunk.len() as u64;
            if seen > max {
                bail!("{name} is larger than the {max} bytes it may be");
            }
            sink(chunk)
        };
        match self {
            Channel::Dir(dir) => {
                use std::io::Read;
                let path = dir.join(name);
                let mut f = std::fs::File::open(&path)
                    .with_context(|| format!("read {}", path.display()))?;
                let mut buf = vec![0u8; 1 << 20];
                loop {
                    let n = f
                        .read(&mut buf)
                        .with_context(|| format!("read {}", path.display()))?;
                    if n == 0 {
                        return Ok(());
                    }
                    take(&buf[..n])?;
                }
            }
            Channel::Http(base) => {
                let url = format!("{base}/{name}");
                let client = reqwest::Client::builder()
                    .connect_timeout(Duration::from_secs(30))
                    .read_timeout(Duration::from_secs(60))
                    .build()?;
                let mut resp = client
                    .get(&url)
                    .send()
                    .await
                    .with_context(|| format!("could not reach {url}"))?
                    .error_for_status()
                    .with_context(|| format!("the channel refused {url}"))?;
                while let Some(chunk) = resp
                    .chunk()
                    .await
                    .with_context(|| format!("download of {url} broke off"))?
                {
                    take(&chunk)?;
                }
                Ok(())
            }
        }
    }
}

/// Everything one `check` or `apply` needs.
pub struct Ctx {
    pub data_dir: PathBuf,
    pub channel: Channel,
    pub root: TrustRoot,
    pub platform: String,
    pub running: Version,
}

impl Ctx {
    fn from_args(a: &ChannelArgs) -> Result<Ctx> {
        let data_dir = a.at.data_dir();
        let roots_path = a
            .trusted_keys
            .clone()
            .unwrap_or_else(|| update_state::update_dir(&data_dir).join("trusted-keys.json"));
        let root = match std::fs::read(&roots_path) {
            Ok(b) => {
                TrustRoot::from_json(&b).map_err(|e| anyhow!("{}: {e}", roots_path.display()))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && a.trusted_keys.is_none() => {
                TrustRoot::embedded()
            }
            Err(e) => return Err(anyhow!("read {}: {e}", roots_path.display())),
        };
        Ok(Ctx {
            data_dir,
            channel: Channel::parse(&a.channel),
            root,
            platform: a.platform.clone().unwrap_or_else(this_platform),
            running: running_release()?,
        })
    }

    fn record(&self) -> Result<UpdateRecord> {
        update_state::load(&self.data_dir).with_context(|| "read the update state")
    }

    fn local(&self, rec: &UpdateRecord) -> Local {
        Local {
            installed_manifest_version: rec.installed_manifest_version,
            highest_timestamp_version: rec.highest_timestamp_version,
            running_release: self.running,
        }
    }

    /// Fetches both documents and verifies them. Writes nothing.
    async fn fetch_verified(&self, rec: &UpdateRecord, now: u64) -> Result<Verified> {
        let ts = self
            .channel
            .small("timestamp.json", manifest::MAX_TIMESTAMP_BYTES)
            .await?;
        let tg = self
            .channel
            .small("targets.json", manifest::MAX_TARGETS_BYTES)
            .await?;
        manifest::verify(&ts, &tg, &self.root, &self.local(rec), now).map_err(|e| {
            anyhow!(
                "the update from {} was refused: {e}",
                self.channel.describe()
            )
        })
    }
}

/// What `check` found.
#[derive(Debug, PartialEq, Eq)]
pub enum Availability {
    UpToDate,
    Available {
        release: String,
        manifest_version: u64,
        description: String,
    },
    /// A newer release that is not C0: reported, never applied by `tenzro update`.
    Held {
        release: String,
        class: Class,
        description: String,
    },
}

fn availability(v: &Verified, local: &Local) -> Availability {
    let t = &v.targets;
    if !v.is_newer(local) {
        Availability::UpToDate
    } else if t.class == Class::C0 {
        Availability::Available {
            release: t.release.clone(),
            manifest_version: t.version,
            description: t.description.clone(),
        }
    } else {
        Availability::Held {
            release: t.release.clone(),
            class: t.class,
            description: t.description.clone(),
        }
    }
}

/// Contacts the channel, verifies, records what was seen.
pub async fn check(ctx: &Ctx, now: u64) -> Result<Availability> {
    let mut rec = ctx.record()?;
    let v = ctx.fetch_verified(&rec, now).await?;
    let found = availability(&v, &ctx.local(&rec));
    rec.highest_timestamp_version = rec.highest_timestamp_version.max(v.timestamp_version);
    rec.last_check = Some(LastCheck {
        checked_ms: now,
        release: v.targets.release.clone(),
        manifest_version: v.targets.version,
    });
    update_state::save(&ctx.data_dir, &rec).context("record the check")?;
    Ok(found)
}

/// What `apply` did.
#[derive(Debug)]
pub struct Applied {
    pub release: String,
    pub installed: install::Installed,
    pub rollback_script: PathBuf,
}

/// Verifies, downloads, hash-checks and installs. The install directory is
/// not touched until every file has matched its signed length and SHA-256.
pub async fn apply(ctx: &Ctx, layout: &Layout, now: u64) -> Result<Applied> {
    apply_with(ctx, layout, now, health::Policy::default()).await
}

/// [`apply`] with the limits the trial runs under.
pub async fn apply_with(
    ctx: &Ctx,
    layout: &Layout,
    now: u64,
    policy: health::Policy,
) -> Result<Applied> {
    install::require_in_place_update(std::env::consts::OS)?;
    let mut rec = ctx.record()?;
    let reading =
        crate::progress::global().wait("Reading the release information", &ctx.channel.describe());
    let v = match ctx.fetch_verified(&rec, now).await {
        Ok(v) => v,
        Err(e) => {
            reading.fail(&format!("{e:#}"));
            return Err(e);
        }
    };
    reading.finish();
    let t = &v.targets;
    match availability(&v, &ctx.local(&rec)) {
        Availability::UpToDate => bail!(
            "nothing to apply: release {} (manifest {}) is not newer than what is installed",
            t.release,
            t.version
        ),
        Availability::Held { release, class, .. } => bail!(
            "release {release} is class {class:?}, not C0: `tenzro update` does not apply it. It needs the coordinated upgrade path"
        ),
        Availability::Available { .. } => {}
    }
    let present = layout.installed_names();
    let wanted: Vec<&manifest::FileEntry> = t
        .files_for(&ctx.platform)
        .filter(|f| present.contains(&f.name.as_str()))
        .collect();
    if wanted.is_empty() {
        bail!(
            "release {} has no file for {} that matches the binaries installed here ({})",
            t.release,
            ctx.platform,
            if present.is_empty() {
                "none found".to_string()
            } else {
                present.join(", ")
            }
        );
    }

    let staging =
        update_state::update_dir(&ctx.data_dir).join(format!("staging-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).with_context(|| format!("create {}", staging.display()))?;
    let steps =
        crate::progress::global().steps(&["Download and check the files", "Install the new files"]);
    let total: u64 = wanted.iter().map(|f| f.length).sum();
    let download = steps.bytes(0, "Update download", Some(total));
    let staged = fetch_files(ctx, &wanted, &staging, &download.reporter()).await;
    let staged = match staged {
        Ok(s) => {
            download.finish();
            s
        }
        Err(e) => {
            download.fail(&format!("{e:#}"));
            let _ = std::fs::remove_dir_all(&staging);
            return Err(e);
        }
    };

    let identity = health::identity_fingerprint(&health::identity_roots(&ctx.data_dir))?;
    let installing = steps.wait(1, "Install", "replacing the files and keeping the old ones");
    let result = install::install(layout, &t.release, &staged);
    let _ = std::fs::remove_dir_all(&staging);
    let installed = match result {
        Ok(i) => {
            installing.finish_with(&format!("installed {}", i.names.join(", ")));
            i
        }
        Err(e) => {
            installing.fail(&format!("{e:#}"));
            return Err(e);
        }
    };
    steps.finish();

    rec.installed_manifest_version = t.version;
    rec.highest_timestamp_version = rec.highest_timestamp_version.max(v.timestamp_version);
    if let Ok(h) = update_state::file_sha256(&layout.binary("tenzro-node")) {
        rec.installed_sha256 = Some(h);
    }
    update_state::save(&ctx.data_dir, &rec).context("record the install")?;
    let previous = installed.previous.rsplit('/').next().map(str::to_string);
    health::begin(&ctx.data_dir, &t.release, previous, now, policy, identity)
        .context("open the update trial")?;
    let script = update_state::update_dir(&ctx.data_dir).join("rollback.sh");
    std::fs::write(&script, install::rollback_script(layout))
        .with_context(|| format!("write {}", script.display()))?;
    Ok(Applied {
        release: t.release.clone(),
        installed,
        rollback_script: script,
    })
}

/// Downloads each file into `staging`, checking length and SHA-256 as it arrives.
async fn fetch_files(
    ctx: &Ctx,
    files: &[&manifest::FileEntry],
    staging: &Path,
    progress: &crate::progress::Reporter,
) -> Result<Vec<(String, PathBuf)>> {
    use std::io::Write;
    let mut out = Vec::new();
    let mut before = 0u64;
    for (n, f) in files.iter().enumerate() {
        progress.message(&format!("{} ({} of {})", f.name, n + 1, files.len()));
        let dest = staging.join(&f.name);
        let mut file =
            std::fs::File::create(&dest).with_context(|| format!("create {}", dest.display()))?;
        let mut hash = Sha256::new();
        let mut got = 0u64;
        ctx.channel
            .stream(&f.path, f.length, &mut |c| {
                hash.update(c);
                got += c.len() as u64;
                progress.set(before + got);
                file.write_all(c).map_err(Into::into)
            })
            .await?;
        progress.message(&format!("checking {}", f.name));
        if got != f.length {
            bail!(
                "{} is {got} bytes; the signed manifest says {}",
                f.path,
                f.length
            );
        }
        let h = hex::encode(hash.finalize());
        if h != f.sha256 {
            bail!(
                "{} hashes to {h}; the signed manifest says {}",
                f.path,
                f.sha256
            );
        }
        file.sync_all()?;
        before += got;
        out.push((f.name.clone(), dest));
    }
    Ok(out)
}

fn layout_of(install_dir: &Option<PathBuf>) -> Result<Layout> {
    match install_dir {
        Some(d) => Ok(Layout::detect(d)),
        None => Layout::of_executable(&std::env::current_exe().context("find the running tenzro")?),
    }
}

/// Asks the channel what it offers. When the channel cannot be read and a
/// signed notice names a newer release, says so before the error is returned.
async fn check_or_explain(ctx: &Ctx, now: u64) -> Result<Availability> {
    match check(ctx, now).await {
        Ok(found) => Ok(found),
        Err(e) => {
            if let Some(n) = notice::cached(&ctx.data_dir, now).filter(|n| {
                n.release()
                    > tenzro_update_notice::notice::Version(
                        ctx.running.0,
                        ctx.running.1,
                        ctx.running.2,
                    )
            }) {
                output::print_warning(&format!(
                    "The release channel could not be read, but a signed notice says Tenzro {} is available (you run {}).",
                    n.version, ctx.running
                ));
            }
            Err(e)
        }
    }
}

fn say_current(ctx: &Ctx) {
    output::print_success(&format!(
        "tenzro {} is current: the channel offers nothing newer",
        ctx.running
    ));
}

fn say_available(ctx: &Ctx, release: &str, manifest_version: u64, description: &str) {
    output::print_info(&format!(
        "C0 update available: {release} (running {}): {description}",
        ctx.running
    ));
    output::print_field("Manifest", &manifest_version.to_string());
}

fn say_held(release: &str, class: Class, description: &str) {
    output::print_warning(&format!(
        "release {release} is class {class:?}, not C0: {description}. `tenzro update` will not apply it; it needs the coordinated upgrade path."
    ));
}

/// What is left to do after an install that restarted nothing.
fn say_next_steps(rollback_script: &Path) {
    println!();
    println!("Next steps:");
    println!("  1. The running node still runs the old binary. Restart it when you choose.");
    println!(
        "     A validator restart takes about 1.5 minutes; do not restart a delegated key holder."
    );
    println!(
        "  2. After the restart:  tenzro update verify   (marks it good, or restores the previous release by itself)"
    );
    println!("     To undo before or after the restart:  tenzro update rollback");
    println!(
        "  3. If tenzro itself will not start:       sh {}",
        rollback_script.display()
    );
}

/// Runs the health gate on the open trial and shows each probe as it happens.
/// `tenzro update verify` and bare `tenzro update` both end here.
async fn gate_with_progress(
    data_dir: &Path,
    layout: &Layout,
    interval: Duration,
    clock: impl FnMut() -> u64,
    sleep: impl AsyncFnMut(Duration),
    mut probe: impl AsyncFnMut() -> Result<health::Observation>,
) -> Result<health::Verdict> {
    let waiting = crate::progress::global().wait(
        "Checking the new release",
        "waiting for the first answer from the node",
    );
    let reporter = waiting.reporter();
    let mut checks = 0u32;
    let verdict = health::run_gate(
        data_dir,
        layout,
        &health::identity_roots(data_dir),
        interval,
        clock,
        sleep,
        async || {
            let seen = probe().await;
            checks += 1;
            match &seen {
                Ok(o) => reporter.message(&format!(
                    "check {checks}: the node answers at block {}",
                    o.height
                )),
                Err(_) => reporter.message(&format!("check {checks}: the node does not answer")),
            }
            seen
        },
    )
    .await;
    let verdict = match verdict {
        Ok(v) => v,
        Err(e) => {
            waiting.fail(&format!("{e:#}"));
            return Err(e);
        }
    };
    match &verdict {
        health::Verdict::Good => waiting.finish_with("the new release is healthy"),
        health::Verdict::RolledBack(_) => waiting.fail("the new release did not stay healthy"),
    }
    Ok(verdict)
}

impl CheckCmd {
    async fn execute(&self) -> Result<()> {
        let ctx = Ctx::from_args(&self.args)?;
        // The signed notice first: it also reaches a machine that cannot read
        // the channel's manifest, through a node.
        let (endpoint, _) = crate::endpoint::resolve();
        let _ = notice::refresh(&ctx.data_dir, &self.args.channel, Some(&endpoint), now_ms()).await;
        match check_or_explain(&ctx, now_ms()).await? {
            Availability::UpToDate => say_current(&ctx),
            Availability::Available {
                release,
                manifest_version,
                description,
            } => {
                say_available(&ctx, &release, manifest_version, &description);
                output::print_info(&tenzro_update_notice::banner::install_hint(
                    std::env::consts::OS,
                    "Install it with",
                ));
            }
            Availability::Held {
                release,
                class,
                description,
            } => say_held(&release, class, &description),
        }
        Ok(())
    }
}

impl ApplyCmd {
    async fn execute(&self) -> Result<()> {
        let ctx = Ctx::from_args(&self.args)?;
        let layout = layout_of(&self.install_dir)?;
        let policy = health::Policy {
            window_ms: self.health_window_secs.saturating_mul(1000),
            max_boot_attempts: self.max_boot_attempts,
            ..health::Policy::default()
        };
        let a = apply_with(&ctx, &layout, now_ms(), policy).await?;
        output::print_success(&format!(
            "Installed {} ({}). Nothing was restarted.",
            a.release,
            a.installed.names.join(", ")
        ));
        output::print_field("Previous kept at", &a.installed.previous);
        say_next_steps(&a.rollback_script);
        Ok(())
    }
}

impl RollbackCmd {
    async fn execute(&self) -> Result<()> {
        install::require_in_place_update(std::env::consts::OS)?;
        let layout = layout_of(&self.install_dir)?;
        let done = install::rollback(&layout)?;
        let data_dir = self.at.data_dir();
        // Keep the advertised digest true to what is on disk now. Best effort:
        // the rollback itself has already happened.
        if let Ok(mut rec) = update_state::load(&data_dir)
            && let Ok(h) = update_state::file_sha256(&layout.binary("tenzro-node"))
        {
            rec.installed_sha256 = Some(h);
            if let Err(e) = update_state::save(&data_dir, &rec) {
                output::print_warning(&format!(
                    "restored the previous binaries but could not update the update state: {e}"
                ));
            }
        }
        if let Err(e) = health::note_manual_rollback(&data_dir) {
            output::print_warning(&format!(
                "restored the previous binaries but could not close the update trial: {e}"
            ));
        }
        output::print_success(&format!(
            "Restored the previous release ({}). Nothing was restarted.",
            done.restored.join(", ")
        ));
        println!("Restart the node when you choose to run it.");
        Ok(())
    }
}

impl BootCheckCmd {
    async fn execute(&self) -> Result<()> {
        let layout = layout_of(&self.install_dir)?;
        // A start is never blocked from here: a failure to count is reported and the node starts.
        match health::record_boot(&self.at.data_dir(), &layout, now_ms()) {
            Ok(health::BootDecision::NoTrial) => {}
            Ok(health::BootDecision::Proceed { attempt }) => {
                output::print_info(&format!("update trial: start {attempt}"))
            }
            Ok(health::BootDecision::RolledBack(reason)) => {
                output::print_warning(&format!(
                    "update rolled back before this start: {reason}. The previous release starts now."
                ));
            }
            Err(e) => output::print_warning(&format!(
                "could not count this start against the update trial: {e}"
            )),
        }
        Ok(())
    }
}

impl VerifyCmd {
    async fn execute(&self) -> Result<()> {
        let layout = layout_of(&self.install_dir)?;
        let data_dir = self.at.data_dir();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;
        let url = self.rpc_url.clone();
        let verdict = gate_with_progress(
            &data_dir,
            &layout,
            Duration::from_secs(self.interval_secs.max(1)),
            now_ms,
            async |d| tokio::time::sleep(d).await,
            async || health::probe_rpc(&client, &url).await,
        )
        .await?;
        match verdict {
            health::Verdict::Good => {
                output::print_success("The new release is healthy and is marked good.")
            }
            health::Verdict::RolledBack(reason) => {
                output::print_warning(&format!(
                    "Rolled back to the previous release: {reason}. Restart the node to run it."
                ));
                bail!("the update failed its health check");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
