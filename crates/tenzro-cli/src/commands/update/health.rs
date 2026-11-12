//! The trial an installed update runs under: a boot-attempt counter and a health window.
//!
//! `tenzro update apply` swaps the binaries into the inactive slot and opens a
//! trial. The trial ends one of two ways:
//!
//! - **Good.** After the node restarts onto the new release, the health gate
//!   (`tenzro update verify`) probes it until it has answered healthy for
//!   enough consecutive checks inside the health window. The release is then
//!   marked good and the previous slot is no longer the fallback.
//! - **Rolled back.** The new release crashes on start (the boot-attempt
//!   counter passes its limit before the node was ever marked good), or the
//!   health window runs out without enough healthy checks, or the node's
//!   identity files changed. The previous release is put back by the same
//!   rename the manual `tenzro update rollback` does, with nothing downloaded.
//!
//! The counter is advanced by `tenzro update boot-check`, which the node unit
//! runs before the node starts. It never blocks a start: after a rollback it
//! lets the restored release come up.
//!
//! State is `<data-dir>/update/trial.json`, written through a temporary file
//! and a rename. It holds no key material; the identity fingerprint is a
//! SHA-256 over the identity files, compared before and after.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_onboarding_types::update_state::{self, update_dir};

use super::install::{self, Layout};

/// How long a new release has to prove itself after its first start.
pub const DEFAULT_WINDOW_MS: u64 = 10 * 60 * 1000;
/// Consecutive healthy probes that end the trial as good.
pub const DEFAULT_STABLE_CHECKS: u32 = 3;
/// Starts a new release may have before it is rolled back, counting the first.
pub const DEFAULT_MAX_BOOT_ATTEMPTS: u32 = 3;

/// The limits a trial runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// The health window, from the first start of the new release.
    pub window_ms: u64,
    /// Consecutive healthy probes needed.
    pub stable_checks: u32,
    /// Starts allowed before the release is marked good.
    pub max_boot_attempts: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            window_ms: DEFAULT_WINDOW_MS,
            stable_checks: DEFAULT_STABLE_CHECKS,
            max_boot_attempts: DEFAULT_MAX_BOOT_ATTEMPTS,
        }
    }
}

/// Where a trial stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrialState {
    /// Installed, not yet confirmed healthy.
    Pending,
    /// Confirmed healthy; the trial is over.
    Good,
    /// Given up on; the previous release was restored.
    RolledBack,
}

/// Why a release was rolled back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// The node was started more times than the limit without being marked good.
    BootAttempts { attempts: u32, limit: u32 },
    /// The health window ended before enough healthy checks.
    WindowExpired { healthy_checks: u32, needed: u32 },
    /// The node's identity files differ from before the update.
    IdentityChanged,
    /// An operator asked for it while the trial ran.
    Manual,
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reason::BootAttempts { attempts, limit } => {
                write!(
                    f,
                    "the new release was started {attempts} times without becoming healthy (limit {limit})"
                )
            }
            Reason::WindowExpired {
                healthy_checks,
                needed,
            } => {
                write!(
                    f,
                    "the health window ended with {healthy_checks} of {needed} healthy checks"
                )
            }
            Reason::IdentityChanged => {
                write!(f, "the node's identity files changed during the update")
            }
            Reason::Manual => write!(f, "rolled back by the operator"),
        }
    }
}

/// `update/trial.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trial {
    /// The release under trial.
    pub release: String,
    /// The release that is restored on failure.
    pub previous: Option<String>,
    pub installed_ms: u64,
    /// When the new release first started; the window runs from here.
    pub first_boot_ms: Option<u64>,
    pub boot_attempts: u32,
    pub window_ms: u64,
    pub stable_checks: u32,
    pub max_boot_attempts: u32,
    /// SHA-256 over the identity files when the update was installed.
    pub identity_sha256: String,
    pub state: TrialState,
    pub reason: Option<Reason>,
    /// Highest certified height a probe saw, so the gate can tell a node that went backwards.
    pub certified_seen: u64,
}

/// The path of the trial file.
pub fn trial_path(data_dir: &Path) -> PathBuf {
    update_dir(data_dir).join("trial.json")
}

/// Reads the trial; `None` when none was ever opened.
pub fn load(data_dir: &Path) -> Result<Option<Trial>> {
    match std::fs::read(trial_path(data_dir)) {
        Ok(b) => Ok(Some(serde_json::from_slice(&b).with_context(|| {
            format!("read {}", trial_path(data_dir).display())
        })?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read {}", trial_path(data_dir).display())),
    }
}

fn save(data_dir: &Path, t: &Trial) -> Result<()> {
    let dir = update_dir(data_dir);
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let tmp = dir.join("trial.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(t)?)
        .with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, trial_path(data_dir)).context("save the trial")
}

/// The files that make a node who it is, under `data_dir`: the device keys,
/// the hybrid key and the passkey store, plus the device-key directory the
/// environment names. An update never writes to any of them.
pub fn identity_roots(data_dir: &Path) -> Vec<PathBuf> {
    let mut roots = vec![
        data_dir.join("device-keys"),
        data_dir.join("hybrid_key.json"),
        data_dir.join("passkey"),
    ];
    if let Some(dir) = std::env::var_os("TENZRO_DEVICE_KEY_DIR") {
        roots.push(PathBuf::from(dir));
    }
    roots
}

fn walk(path: &Path, rel: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) -> Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    if meta.is_dir() {
        for entry in std::fs::read_dir(path).with_context(|| format!("read {}", path.display()))? {
            let entry = entry?;
            walk(&entry.path(), &rel.join(entry.file_name()), out)?;
        }
    } else if meta.is_file() {
        out.push((
            rel.to_path_buf(),
            std::fs::read(path).with_context(|| format!("read {}", path.display()))?,
        ));
    }
    Ok(())
}

/// SHA-256 over the names and bytes of every file under `roots`, in a fixed
/// order. Roots that do not exist add nothing.
pub fn identity_fingerprint(roots: &[PathBuf]) -> Result<String> {
    let mut files = Vec::new();
    for (i, root) in roots.iter().enumerate() {
        let mut found = Vec::new();
        walk(root, Path::new(""), &mut found)?;
        files.extend(
            found
                .into_iter()
                .map(|(rel, bytes)| (PathBuf::from(format!("{i}")).join(rel), bytes)),
        );
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut h = Sha256::new();
    for (name, bytes) in &files {
        h.update((name.as_os_str().len() as u64).to_le_bytes());
        h.update(name.as_os_str().as_encoded_bytes());
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    }
    Ok(hex::encode(h.finalize()))
}

/// Opens a trial for `release`, replacing any earlier one. `identity` is
/// [`identity_fingerprint`] taken before the install.
pub fn begin(
    data_dir: &Path,
    release: &str,
    previous: Option<String>,
    now_ms: u64,
    policy: Policy,
    identity: String,
) -> Result<Trial> {
    let t = Trial {
        release: release.to_string(),
        previous,
        installed_ms: now_ms,
        first_boot_ms: None,
        boot_attempts: 0,
        window_ms: policy.window_ms,
        stable_checks: policy.stable_checks,
        max_boot_attempts: policy.max_boot_attempts,
        identity_sha256: identity,
        state: TrialState::Pending,
        reason: None,
        certified_seen: 0,
    };
    save(data_dir, &t)?;
    Ok(t)
}

/// What the unit does with a start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootDecision {
    /// No trial is open: nothing to count.
    NoTrial,
    /// Start the node; this is start number `attempt` of the trial.
    Proceed { attempt: u32 },
    /// The trial failed before this start: the previous release was restored, start that.
    RolledBack(Reason),
}

/// Counts a node start against the open trial. When the count passes the
/// limit, or the window has already ended with the release never marked
/// good, rolls back instead.
pub fn record_boot(data_dir: &Path, layout: &Layout, now_ms: u64) -> Result<BootDecision> {
    let Some(mut t) = load(data_dir)? else {
        return Ok(BootDecision::NoTrial);
    };
    if t.state != TrialState::Pending {
        return Ok(BootDecision::NoTrial);
    }
    let attempt = t.boot_attempts + 1;
    if attempt > t.max_boot_attempts {
        let reason = Reason::BootAttempts {
            attempts: t.boot_attempts,
            limit: t.max_boot_attempts,
        };
        roll_back(data_dir, layout, &mut t, reason.clone())?;
        return Ok(BootDecision::RolledBack(reason));
    }
    if let Some(first) = t.first_boot_ms
        && now_ms > first.saturating_add(t.window_ms)
    {
        let reason = Reason::WindowExpired {
            healthy_checks: 0,
            needed: t.stable_checks,
        };
        roll_back(data_dir, layout, &mut t, reason.clone())?;
        return Ok(BootDecision::RolledBack(reason));
    }
    t.boot_attempts = attempt;
    t.first_boot_ms.get_or_insert(now_ms);
    save(data_dir, &t)?;
    Ok(BootDecision::Proceed { attempt })
}

/// What one probe of the running node saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    /// The node's head height.
    pub height: u64,
    /// The height finality has certified.
    pub certified: u64,
}

/// How the gate ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Healthy for long enough: the release is marked good.
    Good,
    /// Failed: the previous release was restored.
    RolledBack(Reason),
}

fn restore(data_dir: &Path, layout: &Layout) -> Result<()> {
    install::rollback(layout)?;
    let mut rec = update_state::load(data_dir).context("read the update state")?;
    if let Ok(h) = update_state::file_sha256(&layout.binary("tenzro-node")) {
        rec.installed_sha256 = Some(h);
    }
    update_state::save(data_dir, &rec).context("record the restored digest")
}

fn roll_back(data_dir: &Path, layout: &Layout, t: &mut Trial, reason: Reason) -> Result<()> {
    restore(data_dir, layout)?;
    t.state = TrialState::RolledBack;
    t.reason = Some(reason);
    save(data_dir, t)
}

/// Ends the open trial as rolled back by the operator, after the rollback itself.
pub fn note_manual_rollback(data_dir: &Path) -> Result<()> {
    if let Some(mut t) = load(data_dir)?
        && t.state == TrialState::Pending
    {
        t.state = TrialState::RolledBack;
        t.reason = Some(Reason::Manual);
        save(data_dir, &t)?;
    }
    Ok(())
}

/// Probes the running node until it has been healthy for `stable_checks`
/// consecutive probes, or the window ends. A probe is healthy when the node
/// answers and finality has not gone backwards since the last one. A failed
/// probe resets the run. The identity files are compared first.
///
/// `clock` returns the time in ms; `sleep` waits between probes. Both are
/// parameters so a test runs the whole window in no time.
pub async fn run_gate(
    data_dir: &Path,
    layout: &Layout,
    identity_roots: &[PathBuf],
    interval: Duration,
    mut clock: impl FnMut() -> u64,
    mut sleep: impl AsyncFnMut(Duration),
    mut probe: impl AsyncFnMut() -> Result<Observation>,
) -> Result<Verdict> {
    let mut t =
        load(data_dir)?.ok_or_else(|| anyhow!("no update trial is open: nothing to verify"))?;
    if t.state != TrialState::Pending {
        return Err(anyhow!(
            "the trial for {} already ended as {:?}",
            t.release,
            t.state
        ));
    }
    if identity_fingerprint(identity_roots)? != t.identity_sha256 {
        roll_back(data_dir, layout, &mut t, Reason::IdentityChanged)?;
        return Ok(Verdict::RolledBack(Reason::IdentityChanged));
    }
    let started = *t.first_boot_ms.get_or_insert_with(&mut clock);
    let deadline = started.saturating_add(t.window_ms);
    let mut run = 0u32;
    loop {
        match probe().await {
            Ok(obs) if obs.certified >= t.certified_seen => {
                t.certified_seen = obs.certified;
                run += 1;
            }
            _ => run = 0,
        }
        // A start counted while the gate runs can end the trial itself: the
        // unit gives up on a release that keeps failing to start, and an
        // operator can roll back by hand. The previous release then answers
        // these probes, and its health is not the new release's.
        if let Some(on_disk) = load(data_dir)?
            && on_disk.state == TrialState::RolledBack
        {
            return Ok(Verdict::RolledBack(
                on_disk.reason.unwrap_or(Reason::Manual),
            ));
        }
        if run >= t.stable_checks {
            t.state = TrialState::Good;
            t.boot_attempts = 0;
            save(data_dir, &t)?;
            return Ok(Verdict::Good);
        }
        if clock() >= deadline {
            let reason = Reason::WindowExpired {
                healthy_checks: run,
                needed: t.stable_checks,
            };
            roll_back(data_dir, layout, &mut t, reason.clone())?;
            return Ok(Verdict::RolledBack(reason));
        }
        sleep(interval).await;
    }
}

/// Asks a node's JSON-RPC endpoint for its head and certified height.
pub async fn probe_rpc(client: &reqwest::Client, url: &str) -> Result<Observation> {
    async fn call(client: &reqwest::Client, url: &str, method: &str) -> Result<serde_json::Value> {
        let body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": []});
        let v: serde_json::Value = client
            .post(url)
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        v.get("result")
            .cloned()
            .ok_or_else(|| anyhow!("{method}: no result"))
    }
    fn hex_u64(v: &serde_json::Value) -> Result<u64> {
        let s = v.as_str().ok_or_else(|| anyhow!("expected a hex string"))?;
        u64::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|e| anyhow!("{s}: {e}"))
    }
    let height = hex_u64(&call(client, url, "eth_blockNumber").await?)?;
    let fin = call(client, url, "tenzro_getFinality").await?;
    let certified = hex_u64(
        fin.get("certified")
            .ok_or_else(|| anyhow!("tenzro_getFinality: no certified height"))?,
    )?;
    Ok(Observation { height, certified })
}
