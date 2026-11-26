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
//!
//! An interrupted `apply` is resumed by running it again: downloads continue
//! from the bytes already staged, and an install that stopped half-way is
//! finished with the same verified files. One `apply` or `rollback` runs at a
//! time per data directory ([`lock`]).

pub mod delta;
pub mod health;
pub mod install;
pub mod manifest;
pub mod notice;
pub(crate) mod run;

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use sha2::{Digest, Sha256};
use tenzro_onboarding_types::update_state::{self, LastCheck, UpdateRecord};

use self::install::Layout;
use self::manifest::{Class, Local, TrustRoot, Verified, Version};
use crate::output;

const DEFAULT_CHANNEL: &str = "stable";

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
    /// Write the delta package that rebuilds a release file from the one it replaces (for publishers)
    MakeDelta(MakeDeltaCmd),
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
            Self::MakeDelta(c) => c.execute(),
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
    /// The release channel: `stable`, `security` or `beta`; an https URL; or a local directory holding timestamp.json, targets.json and the files (spell a directory named like a channel as `./<name>`).
    #[arg(long, env = "TENZRO_UPDATE_CHANNEL", default_value = DEFAULT_CHANNEL)]
    channel: String,
    /// JSON file of trusted keys; default `<data-dir>/update/trusted-keys.json`, else the built-in root.
    #[arg(long)]
    trusted_keys: Option<PathBuf>,
    /// Platform to fetch, `<arch>-<os>` or `<arch>-<os>-<build kind>`; defaults to this machine's and the installed build kind.
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
    /// The install directory whose release is compared with the channel's; defaults to where this `tenzro` runs from.
    #[arg(long)]
    install_dir: Option<PathBuf>,
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

/// The manifest platform that holds the files of build `kind` for `platform`
/// (`<arch>-<os>`): the platform itself for the CPU build, for an install
/// that records no kind and on macOS, which has one build per architecture;
/// `<arch>-<os>-<kind>` for every other kind.
fn channel_platform(platform: &str, kind: Option<&str>) -> String {
    match kind {
        Some(kind) if kind != "cpu" && !platform.ends_with("-macos") => {
            format!("{platform}-{kind}")
        }
        _ => platform.to_string(),
    }
}

/// How long the new node may take to answer `hardware`.
const START_CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Whether the node at `node` starts on this machine, by its own check
/// (`tenzro-node hardware`): only an exit of 0 with the line `startup: ok`
/// is a yes. A refusal, another exit, no verdict, a program that cannot be
/// run (a missing library, a file for another machine) and no answer within
/// [`START_CHECK_TIMEOUT`] are each a no, with the reason.
///
/// A file that was just written can be refused as busy for a moment while
/// another process still holds it open for writing, so that is tried again.
pub fn start_verdict(node: &Path) -> std::result::Result<(), String> {
    start_verdict_within(node, START_CHECK_TIMEOUT)
}

fn start_verdict_within(
    node: &Path,
    timeout: std::time::Duration,
) -> std::result::Result<(), String> {
    use std::io::Read;
    let spawn = || {
        std::process::Command::new(node)
            .arg("hardware")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
    };
    let mut child = spawn();
    for _ in 0..20 {
        match &child {
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(std::time::Duration::from_millis(50));
                child = spawn();
            }
            _ => break,
        }
    }
    let mut child = child.map_err(|e| format!("it cannot be run: {e}"))?;
    let started = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("it gave no answer within {} s", timeout.as_secs()));
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
            Err(e) => return Err(format!("it could not be waited for: {e}")),
        }
    };
    let mut out = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_string(&mut out);
    }
    if let Some(reason) = out.lines().find_map(|l| {
        l.trim()
            .strip_prefix("startup: refused (")?
            .strip_suffix(')')
            .map(str::to_string)
    }) {
        return Err(reason);
    }
    if !status.success() {
        return Err(match status.code() {
            Some(code) => format!("its check exited with {code}"),
            None => "its check was killed".to_string(),
        });
    }
    if !out.lines().any(|l| l.trim() == "startup: ok") {
        return Err("its check gave no startup verdict".to_string());
    }
    Ok(())
}

/// The build kind a manifest platform names: the part after `<arch>-<os>`,
/// `cpu` for a bare `<arch>-<os>`, none on macOS (one build per architecture).
fn kind_of_platform(platform: &str) -> Option<String> {
    let mut parts = platform.splitn(3, '-');
    let (_, os, kind) = (parts.next(), parts.next(), parts.next());
    match (os, kind) {
        (Some(_), Some(kind)) => Some(kind.to_string()),
        (Some("macos"), None) => None,
        _ => Some("cpu".to_string()),
    }
}

/// The `<arch>-<os>` of a manifest platform.
fn base_platform(platform: &str) -> &str {
    match platform.match_indices('-').nth(1) {
        Some((i, _)) => &platform[..i],
        None => platform,
    }
}

/// What an operator can do when the new node of build `kind` refuses this
/// machine: an update never changes the build kind, the installer does.
fn after_refusal(kind: Option<&str>) -> String {
    let os = std::env::consts::OS;
    match kind {
        Some(kind) if kind != "cpu" && os != "macos" => {
            let cpu = format!("tenzro-node-{os}-{}-cpu", std::env::consts::ARCH);
            let flag = if os == "windows" {
                "-Target"
            } else {
                "--target"
            };
            format!(
                "The installed release stays current and nothing was changed. `tenzro update` keeps the {kind} build; to run the CPU build on this machine instead, run the installer with {flag} {cpu}"
            )
        }
        _ => "The installed release stays current and nothing was changed".to_string(),
    }
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
        let s = tenzro_update_notice::rollout::channel_url(s);
        let s = s.as_str();
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
        self.stream(name, 0, max as u64, &mut |c| {
            out.extend_from_slice(c);
            Ok(())
        })
        .await?;
        Ok(out)
    }

    /// Feeds `name` from byte `from` on to `sink` in chunks; stops with an
    /// error as soon as the file would be longer than `max` bytes. A server
    /// that ignores the range and sends the whole file has its first `from`
    /// bytes skipped here.
    async fn stream(
        &self,
        name: &str,
        from: u64,
        max: u64,
        sink: &mut (dyn FnMut(&[u8]) -> Result<()> + Send),
    ) -> Result<()> {
        let mut seen = from;
        let mut take = |chunk: &[u8]| -> Result<()> {
            seen += chunk.len() as u64;
            if seen > max {
                bail!("{name} is larger than the {max} bytes it may be");
            }
            sink(chunk)
        };
        match self {
            Channel::Dir(dir) => {
                use std::io::{Read, Seek};
                let path = dir.join(name);
                let mut f = std::fs::File::open(&path)
                    .with_context(|| format!("read {}", path.display()))?;
                f.seek(std::io::SeekFrom::Start(from))
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
                let mut req = client.get(&url);
                if from > 0 {
                    req = req.header(reqwest::header::RANGE, format!("bytes={from}-"));
                }
                let mut resp = req
                    .send()
                    .await
                    .with_context(|| format!("could not reach {url}"))?
                    .error_for_status()
                    .with_context(|| format!("the channel refused {url}"))?;
                let mut skip = if resp.status() == reqwest::StatusCode::PARTIAL_CONTENT {
                    0
                } else {
                    from
                };
                while let Some(chunk) = resp
                    .chunk()
                    .await
                    .with_context(|| format!("download of {url} broke off"))?
                {
                    let cut = skip.min(chunk.len() as u64) as usize;
                    skip -= cut as u64;
                    if cut < chunk.len() {
                        take(&chunk[cut..])?;
                    }
                }
                if skip > 0 {
                    bail!("{url} is shorter than the {from} bytes already downloaded");
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
    /// Whether `platform` was named on the command line: it is then used as
    /// it is, and the kind it names is the kind recorded.
    pub platform_given: bool,
    /// Asks a new node built for this machine whether it starts here
    /// ([`start_verdict`]).
    pub start_check: fn(&Path) -> std::result::Result<(), String>,
    /// The version of this `tenzro`.
    pub running: Version,
    /// Where this `tenzro` runs from.
    pub exe: PathBuf,
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
            platform_given: a.platform.is_some(),
            start_check: start_verdict,
            running: running_release()?,
            exe: std::env::current_exe().context("find the running tenzro")?,
        })
    }

    /// The build kind an update of `layout` installs: the installed kind,
    /// or the one a platform named on the command line names.
    fn build_kind(&self, layout: &Layout) -> Option<String> {
        if self.platform_given {
            kind_of_platform(&self.platform)
        } else {
            layout.build_kind()
        }
    }

    /// The manifest platform `layout` takes its files from.
    fn files_platform(&self, layout: &Layout) -> String {
        if self.platform_given {
            self.platform.clone()
        } else {
            channel_platform(&self.platform, self.build_kind(layout).as_deref())
        }
    }

    fn record(&self) -> Result<UpdateRecord> {
        update_state::load(&self.data_dir).with_context(|| "read the update state")
    }

    /// The release installed in `layout`: what a new release is compared with.
    fn installed(&self, layout: &Layout) -> Result<Version> {
        install::installed_release(layout, self.running, &self.exe)
    }

    fn local(&self, rec: &UpdateRecord, layout: &Layout) -> Result<Local> {
        Ok(Local {
            installed_manifest_version: rec.installed_manifest_version,
            highest_timestamp_version: rec.highest_timestamp_version,
            installed_release: self.installed(layout)?,
        })
    }

    /// Fetches both documents and verifies them. Writes nothing.
    async fn fetch_verified(&self, local: &Local, now: u64) -> Result<Verified> {
        let ts = self
            .channel
            .small("timestamp.json", manifest::MAX_TIMESTAMP_BYTES)
            .await?;
        let tg = self
            .channel
            .small("targets.json", manifest::MAX_TARGETS_BYTES)
            .await?;
        manifest::verify(&ts, &tg, &self.root, local, now).map_err(|e| {
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

/// Whether an earlier `apply` of exactly this update switched `current` and
/// stopped before recording it: `current` names the offered release, its
/// manifest number was never recorded, and its files are still staged (the
/// staging directory is removed only once the install is recorded).
fn unfinished(ctx: &Ctx, layout: &Layout, local: &Local, v: &Verified) -> bool {
    let t = &v.targets;
    let present = layout.installed_names();
    let staging = staging_dir(&ctx.data_dir);
    let platform = ctx.files_platform(layout);
    let mut wanted = t
        .files_for(&platform)
        .filter(|f| present.contains(&f.name.as_str()))
        .peekable();
    t.version > local.installed_manifest_version
        && layout.current_release().as_deref() == Some(t.release.as_str())
        && wanted.peek().is_some()
        && wanted.all(|f| staging.join(&f.sha256).is_file())
}

/// What the verified channel offers this install. `unfinished` is
/// [`unfinished`]: such an update is offered again so it is completed.
fn availability(v: &Verified, local: &Local, unfinished: bool) -> Availability {
    let t = &v.targets;
    if !v.is_newer(local) && !unfinished {
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

/// Contacts the channel, verifies against the release installed in
/// `layout`, records what was seen.
pub async fn check(ctx: &Ctx, layout: &Layout, now: u64) -> Result<Availability> {
    let mut rec = ctx.record()?;
    let local = ctx.local(&rec, layout)?;
    let v = ctx.fetch_verified(&local, now).await?;
    let found = availability(&v, &local, unfinished(ctx, layout, &local, &v));
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
    install::require_in_place_update(std::env::consts::OS, layout)?;
    let _lock = lock(&ctx.data_dir).await?;
    let mut rec = ctx.record()?;
    let local = ctx.local(&rec, layout)?;
    let reading =
        crate::progress::global().wait("Reading the release information", &ctx.channel.describe());
    let v = match ctx.fetch_verified(&local, now).await {
        Ok(v) => v,
        Err(e) => {
            reading.fail(&format!("{e:#}"));
            return Err(e);
        }
    };
    reading.finish();
    let t = &v.targets;
    match availability(&v, &local, unfinished(ctx, layout, &local, &v)) {
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
    let kind = ctx.build_kind(layout);
    let platform = ctx.files_platform(layout);
    // A platform named by hand installs the kind it names, and never replaces
    // the kind this install records with another one.
    if let Some(recorded) = layout.build_kind().filter(|_| ctx.platform_given)
        && kind.as_deref() != Some(recorded.as_str())
    {
        bail!(
            "this install is the {recorded} build and --platform {} names {}; `tenzro update` does not change the build kind. Nothing was changed; install the other build with the installer",
            ctx.platform,
            kind.as_deref()
                .map_or("a platform with no build kind".to_string(), |k| format!(
                    "the {k} build"
                )),
        );
    }
    let wanted: Vec<&manifest::FileEntry> = t
        .files_for(&platform)
        .filter(|f| present.contains(&f.name.as_str()))
        .collect();
    if wanted.is_empty() && platform != ctx.platform {
        bail!(
            "release {} has no {} build for {} in this channel (no file under platform {platform}), and `tenzro update` does not replace one build kind with another. Nothing was changed; install the release with the installer",
            t.release,
            kind.as_deref().unwrap_or_default(),
            ctx.platform,
        );
    }
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

    // An install that keeps libraries beside its binaries takes the new
    // release's from the libraries document; one that keeps none never reads it.
    let libraries = if install::has_libraries(layout) {
        let bytes = ctx
            .channel
            .small("libraries.json", manifest::MAX_LIBRARIES_BYTES)
            .await
            .with_context(|| {
                format!(
                    "this install keeps libraries beside its binaries and the libraries of release {} could not be read; nothing was changed",
                    t.release
                )
            })?;
        let libraries = manifest::verify_libraries(&bytes, &ctx.root, &v).map_err(|e| {
            anyhow!(
                "the libraries of release {} from {} were refused: {e}; nothing was changed",
                t.release,
                ctx.channel.describe()
            )
        })?;
        if libraries.files_for(&platform).next().is_none() {
            bail!(
                "release {} lists no libraries for {platform}, and this install keeps libraries beside its binaries; nothing was changed",
                t.release
            );
        }
        Some(libraries)
    } else {
        None
    };
    let all: Vec<&manifest::FileEntry> = wanted
        .iter()
        .copied()
        .chain(libraries.iter().flat_map(|l| l.files_for(&platform)))
        .collect();

    let staging = staging_dir(&ctx.data_dir);
    std::fs::create_dir_all(&staging).with_context(|| format!("create {}", staging.display()))?;
    let steps =
        crate::progress::global().steps(&["Download and check the files", "Install the new files"]);
    let total: u64 = all.iter().map(|f| f.length).sum();
    let download = steps.bytes(0, "Update download", Some(total));
    // A failed download keeps what arrived, so the next run resumes it.
    let staged = fetch_files(ctx, layout, &all, &staging, &download.reporter()).await;
    let mut staged = match staged {
        Ok(s) => {
            download.finish();
            s
        }
        Err(e) => {
            download.fail(&format!("{e:#}"));
            return Err(e);
        }
    };

    let library_files = staged.split_off(wanted.len());
    let staged_libraries = libraries.as_ref().map(|l| install::StagedLibraries {
        files: library_files,
        links: l
            .links_for(&platform)
            .map(|k| (k.name.clone(), k.target.clone()))
            .collect(),
    });

    let identity = health::identity_fingerprint(&health::identity_roots(&ctx.data_dir))?;
    let installing = steps.wait(1, "Install", "replacing the files and keeping the old ones");
    // A build for this machine is asked whether it starts here, from where
    // it will run and before `current` is switched. A refusal leaves the
    // installed release current: an update never moves to another build kind.
    let native = base_platform(&ctx.platform) == this_platform();
    let attempt = install::install(
        layout,
        &t.release,
        &staged,
        kind.as_deref(),
        staged_libraries.as_ref(),
        &|node| {
            if !native {
                return Ok(());
            }
            (ctx.start_check)(node).map_err(|reason| {
                anyhow!(
                    "the new tenzro-node does not start on this machine ({reason}). {}",
                    after_refusal(kind.as_deref())
                )
            })
        },
    );
    let installed = match attempt {
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

    // The trial opens before the install is recorded: a run that stops in
    // between leaves the manifest number unrecorded, so the next run installs
    // the same release again (a no-op on the files) and opens the trial.
    health::begin(
        &ctx.data_dir,
        &t.release,
        installed.previous_release.clone(),
        now,
        policy,
        identity,
    )
    .context("open the update trial")?;
    let script = write_rollback_script(&ctx.data_dir, layout)?;
    rec.installed_manifest_version = t.version;
    rec.highest_timestamp_version = rec.highest_timestamp_version.max(v.timestamp_version);
    if let Ok(h) = update_state::file_sha256(&layout.binary("tenzro-node")) {
        rec.installed_sha256 = Some(h);
    }
    update_state::save(&ctx.data_dir, &rec).context("record the install")?;
    let _ = std::fs::remove_dir_all(&staging);
    Ok(Applied {
        release: t.release.clone(),
        installed,
        rollback_script: script,
    })
}

/// Where downloads are staged: one directory per data directory, files named
/// by their signed SHA-256, so an interrupted download is resumed only into
/// the file it was for.
pub fn staging_dir(data_dir: &Path) -> PathBuf {
    update_state::update_dir(data_dir).join("staging")
}

/// Holds the update lock of `data_dir` until dropped. A second `apply` or
/// `rollback` on the same data directory is refused while one runs, since
/// both write the staging directory, the install and the update state.
pub struct UpdateLock {
    _file: std::fs::File,
}

/// How long `lock` keeps trying before it reports another update. A process
/// this one starts holds a copy of every open file until it runs its program,
/// so for that moment a lock this process already released still looks held.
const LOCK_WAIT: Duration = Duration::from_millis(500);

pub async fn lock(data_dir: &Path) -> Result<UpdateLock> {
    let dir = update_state::update_dir(data_dir);
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let path = dir.join("update.lock");
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    let started = std::time::Instant::now();
    loop {
        match f.try_lock() {
            Ok(()) => return Ok(UpdateLock { _file: f }),
            Err(std::fs::TryLockError::WouldBlock) if started.elapsed() < LOCK_WAIT => {
                tokio::time::sleep(Duration::from_millis(10)).await
            }
            Err(std::fs::TryLockError::WouldBlock) => bail!(
                "another `tenzro update` is running on {}; wait for it to finish",
                data_dir.display()
            ),
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(e).context("take the update lock");
            }
        }
    }
}

/// Writes the script that restores the previous release without the new
/// `tenzro`: `rollback.sh` on Unix, `rollback.cmd` on Windows.
fn write_rollback_script(data_dir: &Path, layout: &Layout) -> Result<PathBuf> {
    let dir = update_state::update_dir(data_dir);
    let (path, text) = match layout {
        Layout::Versioned { root } if cfg!(windows) => (
            dir.join("rollback.cmd"),
            install::rollback_cmd(root, data_dir),
        ),
        _ => (dir.join("rollback.sh"), install::rollback_script(layout)),
    };
    std::fs::write(&path, text).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

/// Downloads each file into `staging`, checking length and SHA-256 as it
/// arrives. A file is staged as `<sha256>.part` and renamed to `<sha256>`
/// once it matches. A partial file left by an interrupted run is continued
/// from where it stopped (its bytes are hashed again first); a complete one
/// is not downloaded again. A file that fails its check is deleted, so the
/// next run starts it over.
///
/// Before a full download, the delta from the file installed under the same
/// name in `layout` is tried ([`delta`]). It is kept only when it rebuilds
/// exactly the file the signed manifest describes; a missing or wrong delta
/// falls back to the full file.
async fn fetch_files(
    ctx: &Ctx,
    layout: &Layout,
    files: &[&manifest::FileEntry],
    staging: &Path,
    progress: &crate::progress::Reporter,
) -> Result<Vec<(String, PathBuf)>> {
    use std::io::{Read, Write};
    let mut out = Vec::new();
    let mut before = 0u64;
    for (n, f) in files.iter().enumerate() {
        progress.message(&format!("{} ({} of {})", f.name, n + 1, files.len()));
        let done = staging.join(&f.sha256);
        if update_state::file_sha256(&done).is_ok_and(|h| h == f.sha256) {
            before += f.length;
            progress.set(before);
            out.push((f.name.clone(), done));
            continue;
        }
        if let Some(rebuilt) = from_delta(ctx, layout, f).await {
            let part = staging.join(format!("{}.part", f.sha256));
            std::fs::write(&part, &rebuilt).with_context(|| format!("write {}", part.display()))?;
            std::fs::rename(&part, &done).with_context(|| format!("stage {}", done.display()))?;
            progress.message(&format!("{}: rebuilt from the installed file", f.name));
            before += f.length;
            progress.set(before);
            out.push((f.name.clone(), done));
            continue;
        }
        let part = staging.join(format!("{}.part", f.sha256));
        let mut hash = Sha256::new();
        let mut got = 0u64;
        if let Ok(mut old) = std::fs::File::open(&part) {
            let len = old.metadata().map(|m| m.len()).unwrap_or(u64::MAX);
            if len <= f.length {
                let mut buf = vec![0u8; 1 << 20];
                loop {
                    let k = old
                        .read(&mut buf)
                        .with_context(|| format!("read {}", part.display()))?;
                    if k == 0 {
                        break;
                    }
                    hash.update(&buf[..k]);
                    got += k as u64;
                }
            }
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(got == 0)
            .open(&part)
            .with_context(|| format!("open {}", part.display()))?;
        if got > 0 {
            file.set_len(got)?;
            std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(got))?;
            progress.message(&format!("{}: resuming at byte {got}", f.name));
        }
        progress.set(before + got);
        if got < f.length {
            ctx.channel
                .stream(&f.path, got, f.length, &mut |c| {
                    hash.update(c);
                    got += c.len() as u64;
                    progress.set(before + got);
                    file.write_all(c).map_err(Into::into)
                })
                .await?;
        }
        progress.message(&format!("checking {}", f.name));
        if got != f.length {
            // The stream ended without an error, so the channel's file is
            // this short: what is staged cannot be continued.
            drop(file);
            let _ = std::fs::remove_file(&part);
            bail!(
                "{} is {got} bytes; the signed manifest says {}",
                f.path,
                f.length
            );
        }
        let h = hex::encode(hash.finalize());
        if h != f.sha256 {
            drop(file);
            let _ = std::fs::remove_file(&part);
            bail!(
                "{} hashes to {h}; the signed manifest says {}",
                f.path,
                f.sha256
            );
        }
        file.sync_all()?;
        drop(file);
        std::fs::rename(&part, &done).with_context(|| format!("stage {}", done.display()))?;
        before += got;
        out.push((f.name.clone(), done));
    }
    Ok(out)
}

/// Puts the previous release back in `layout`, as `tenzro update rollback`
/// does, and keeps the update record and the update trial true to it.
/// Restarts nothing.
pub(crate) async fn roll_back(layout: &Layout, data_dir: &Path) -> Result<install::RolledBack> {
    install::require_in_place_update(std::env::consts::OS, layout)?;
    let _lock = lock(data_dir).await?;
    let done = install::rollback(layout)?;
    // Keep the advertised digest true to what is on disk now. Best effort:
    // the rollback itself has already happened.
    if let Ok(mut rec) = update_state::load(data_dir)
        && let Ok(h) = update_state::file_sha256(&layout.binary("tenzro-node"))
    {
        rec.installed_sha256 = Some(h);
        if let Err(e) = update_state::save(data_dir, &rec) {
            output::print_warning(&format!(
                "restored the previous binaries but could not update the update state: {e}"
            ));
        }
    }
    if let Err(e) = health::note_manual_rollback(data_dir) {
        output::print_warning(&format!(
            "restored the previous binaries but could not close the update trial: {e}"
        ));
    }
    Ok(done)
}

/// The release file `f`, rebuilt from the file installed under its name in
/// `layout` with the channel's delta, when the channel has a delta from that
/// file and it rebuilds exactly the signed file. `None` sends the caller to
/// the full download.
async fn from_delta(ctx: &Ctx, layout: &Layout, f: &manifest::FileEntry) -> Option<Vec<u8>> {
    let base = std::fs::read(layout.binary(&f.name)).ok()?;
    let base_sha = hex::encode(Sha256::digest(&base));
    // A delta as large as the file saves nothing.
    let cap = usize::try_from(f.length).ok()?;
    let delta = ctx
        .channel
        .small(&delta::delta_path(&f.path, &base_sha), cap)
        .await
        .ok()?;
    match delta::apply(&base, &delta, f.length, &f.sha256) {
        Ok(rebuilt) => Some(rebuilt),
        Err(e) => {
            output::print_warning(&format!(
                "{}: the channel's delta was not used ({e}); downloading the full file",
                f.name
            ));
            None
        }
    }
}

/// `tenzro update make-delta`: for a publisher, the delta package that
/// rebuilds `target` from `base`, written to `out`. The channel serves it at
/// `<target's path>.from-<base sha256>.delta`, beside the full file.
#[derive(Debug, Parser)]
pub struct MakeDeltaCmd {
    /// The file the delta applies to: the binary of the earlier release
    #[arg(long)]
    base: PathBuf,
    /// The file the delta rebuilds: the binary of the new release
    #[arg(long)]
    target: PathBuf,
    /// Where to write the delta
    #[arg(long)]
    out: PathBuf,
}

impl MakeDeltaCmd {
    fn execute(&self) -> Result<()> {
        let read = |p: &Path| std::fs::read(p).with_context(|| format!("read {}", p.display()));
        let (base, target) = (read(&self.base)?, read(&self.target)?);
        let d = delta::encode(&base, &target);
        delta::apply(
            &base,
            &d,
            target.len() as u64,
            &hex::encode(Sha256::digest(&target)),
        )
        .map_err(|e| anyhow!("the delta does not rebuild the target: {e}"))?;
        std::fs::write(&self.out, &d).with_context(|| format!("write {}", self.out.display()))?;
        output::print_field("Base SHA-256", &hex::encode(Sha256::digest(&base)));
        output::print_field(
            "Delta",
            &format!("{} bytes for a {}-byte file", d.len(), target.len()),
        );
        output::print_info(&format!(
            "Serve it as <the target's path>.from-{}.delta",
            hex::encode(Sha256::digest(&base))
        ));
        Ok(())
    }
}

fn layout_of(install_dir: &Option<PathBuf>) -> Result<Layout> {
    match install_dir {
        Some(d) => Ok(Layout::detect(d)),
        None => Layout::of_executable(&std::env::current_exe().context("find the running tenzro")?),
    }
}

/// Asks the channel what it offers. When the channel cannot be read and a
/// signed notice names a newer release, says so before the error is returned.
async fn check_or_explain(ctx: &Ctx, layout: &Layout, now: u64) -> Result<Availability> {
    match check(ctx, layout, now).await {
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

fn say_current(ctx: &Ctx, layout: &Layout) {
    let installed = ctx.installed(layout).map_or_else(
        |_| "the installed release".to_string(),
        |v| format!("tenzro {v}"),
    );
    output::print_success(&format!(
        "{installed} is current: the channel offers nothing newer"
    ));
}

fn say_available(
    ctx: &Ctx,
    layout: &Layout,
    release: &str,
    manifest_version: u64,
    description: &str,
) {
    let installed = ctx
        .installed(layout)
        .map_or_else(|_| "unknown".to_string(), |v| v.to_string());
    output::print_info(&format!(
        "C0 update available: {release} (installed {installed}): {description}"
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
    let run = if rollback_script.extension().is_some_and(|e| e == "cmd") {
        ""
    } else {
        "sh "
    };
    println!(
        "  3. If tenzro itself will not start:       {run}{}",
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
        let layout = layout_of(&self.install_dir)?;
        // The signed notice first: it also reaches a machine that cannot read
        // the channel's manifest, through a node.
        let (endpoint, _) = crate::endpoint::resolve();
        let _ = notice::refresh(&ctx.data_dir, &self.args.channel, Some(&endpoint), now_ms()).await;
        match check_or_explain(&ctx, &layout, now_ms()).await? {
            Availability::UpToDate => say_current(&ctx, &layout),
            Availability::Available {
                release,
                manifest_version,
                description,
            } => {
                say_available(&ctx, &layout, &release, manifest_version, &description);
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
        let done = roll_back(&layout_of(&self.install_dir)?, &self.at.data_dir()).await?;
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
