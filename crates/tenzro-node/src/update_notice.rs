//! Release notices on the node: serving, gossip, and the fetch from the
//! downloads host.
//!
//! A node keeps the newest verified notice on disk
//! (`<data_dir>/update/notice.json`, see [`tenzro_update_notice::store`]) and
//! does three things with it:
//!
//! - serves it through the read-only `tenzro_getUpdateNotice` method, from an
//!   in-memory copy refreshed at most every [`CACHE_REFRESH`], behind a global
//!   rate limit. A client that cannot reach the downloads host asks any node;
//!   it verifies the notice itself, so the node is not trusted;
//! - passes a newer notice it verified on to its gossip neighbours on the
//!   [`TOPIC`] topic. The gossip message is the existing `Custom` payload, so
//!   a node that predates notices is not affected: it never joins the topic
//!   and nothing about its wire format changes;
//! - fetches `notice.json` from the downloads host every [`FETCH_EVERY`] and
//!   re-publishes what it holds every [`REPUBLISH_EVERY`], so a node that joins
//!   later still hears of it.
//!
//! A notice is data. Nothing here installs, downloads or runs anything.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tenzro_network::{
    MessagePayload, NetworkMessage, NetworkService, TenzroNetworkService, ValidatedMessage,
};
use tenzro_update_notice::banner::EpochView;
use tenzro_update_notice::notice::{self, Notice, NoticeError, Policy, Version};
use tenzro_update_notice::{NoticeStore, Offer};
use tokio::sync::mpsc;

use crate::gcra::{GcraConfig, GcraDecision, GcraLimiter};

/// The gossip topic notices travel on.
pub const TOPIC: &str = "tenzro/update-notice";

/// The channel a node follows unless `TENZRO_RELEASE_CHANNEL` says otherwise.
pub const DEFAULT_CHANNEL: &str = "stable";

/// Where the downloads host publishes the channel, unless `TENZRO_UPDATE_CHANNEL` names
/// another (`stable`, `security`, `beta` or a URL).
pub const DEFAULT_CHANNEL_URL: &str = "https://downloads.tenzro.com/update/stable";

/// How long an in-memory copy of the notice is served before disk is read again.
pub const CACHE_REFRESH: Duration = Duration::from_secs(30);

/// How long a client may keep an answer, as the method reports it.
pub const CACHE_TTL_SECS: u64 = 300;

/// How often the downloads host is asked.
pub const FETCH_EVERY: Duration = Duration::from_secs(6 * 3600);

/// How often a node re-publishes the notice it holds.
pub const REPUBLISH_EVERY: Duration = Duration::from_secs(6 * 3600);

/// Sustained rate of `tenzro_getUpdateNotice` across all callers: one answer
/// per this period, with a burst of [`RPC_BURST`].
pub const RPC_PERIOD: Duration = Duration::from_millis(500);

/// Burst of `tenzro_getUpdateNotice` answers.
pub const RPC_BURST: u32 = 20;

/// JSON-RPC code of a refused call, the same as the per-address limit.
pub const RPC_ERR_RATE_LIMITED: i32 = crate::ip_rate_limit::RPC_ERR_RATE_LIMITED;

fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

/// What the node does with a notice it received over gossip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Judgement {
    /// Newer than what the node held and verified: kept, and passed on.
    Forward(Box<Notice>),
    /// Valid but nothing new (already held, older, expired, another channel):
    /// not passed on, the sender is not blamed.
    Drop,
    /// Not signed by a trusted key or not a notice: not passed on, and the
    /// sender is scored down.
    Reject,
}

struct Held {
    at: Instant,
    raw: Option<Vec<u8>>,
    notice: Option<Notice>,
}

/// One node's notice state.
pub struct NoticeHub {
    store: NoticeStore,
    keys: Vec<Vec<u8>>,
    channel: String,
    running: Version,
    limiter: GcraLimiter,
    held: Mutex<Option<Held>>,
    data_dir: PathBuf,
    /// The newest version the installer was already started for from this
    /// process, so a notice re-broadcast does not start it again.
    auto_installed: Mutex<Option<String>>,
    /// Whether an install started from here is still running.
    installing: AtomicBool,
}

impl NoticeHub {
    /// A hub over `data_dir` for `channel`, running `running`, trusting `keys`.
    pub fn new(data_dir: &Path, channel: &str, running: Version, keys: Vec<Vec<u8>>) -> Self {
        Self {
            store: NoticeStore::open(data_dir),
            keys,
            channel: channel.to_string(),
            running,
            limiter: GcraLimiter::new(GcraConfig {
                period: RPC_PERIOD,
                burst: RPC_BURST,
            }),
            held: Mutex::new(None),
            data_dir: data_dir.to_path_buf(),
            auto_installed: Mutex::new(None),
            installing: AtomicBool::new(false),
        }
    }

    /// Whether the operator armed automatic installs for this node.
    pub fn auto_install_armed(&self) -> bool {
        tenzro_update_notice::banner::Prefs::load(&self.data_dir).auto_install
    }

    /// Takes the one place for an automatic install of `version`: false
    /// while another install runs, or when `version` was already installed
    /// from here.
    fn begin_auto_install(&self, version: &str) -> bool {
        if self.auto_installed.lock().as_deref() == Some(version) {
            return false;
        }
        self.begin_install()
    }

    /// Takes the one place for an install: false while another runs.
    fn begin_install(&self) -> bool {
        !self.installing.swap(true, Ordering::AcqRel)
    }

    /// Ends the install [`Self::begin_install`] admitted. `version` is kept
    /// as done when the installer was started, so it is not started again
    /// automatically for the same release; a start that failed is tried again
    /// on the next notice.
    fn end_install(&self, started: Option<&str>) {
        if let Some(version) = started {
            *self.auto_installed.lock() = Some(version.to_string());
        }
        self.installing.store(false, Ordering::Release);
    }

    /// A hub for this binary: the embedded release key (or the trusted keys
    /// file), the channel from the environment, and this binary's version.
    pub fn for_node(data_dir: &Path) -> Self {
        let keys = notice::trusted_keys(data_dir).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "trusted keys file unreadable; release notices use the embedded release key");
            vec![notice::release_key_sec1()]
        });
        let channel =
            std::env::var("TENZRO_RELEASE_CHANNEL").unwrap_or_else(|_| DEFAULT_CHANNEL.to_string());
        let running = env!("CARGO_PKG_VERSION")
            .parse()
            .expect("the package version is major.minor.patch");
        Self::new(data_dir, &channel, running, keys)
    }

    /// The keys a notice must verify under now: the ones governance put on
    /// chain when it did, else the node's own.
    fn trusted(&self) -> Vec<Vec<u8>> {
        effective_keys(&self.keys, &GOVERNED_KEYS.read())
    }

    fn policy<'a>(&'a self, keys: &'a [Vec<u8>], now_ms: u64) -> Policy<'a> {
        Policy {
            keys,
            channel: &self.channel,
            running: self.running,
            now_ms,
        }
    }

    /// The newest verified notice and its signed bytes.
    pub fn current(&self, now_ms: u64) -> Option<(Notice, Vec<u8>)> {
        let keys = self.trusted();
        self.store.cached(&self.policy(&keys, now_ms))
    }

    /// The newest verified notice when it names a release newer than the one
    /// running: what the operator can install.
    pub fn newer(&self, now_ms: u64) -> Option<Notice> {
        self.held(now_ms).1.filter(|n| n.release() > self.running)
    }

    /// Verifies `bytes`; keeps them if they are newer than what is held.
    pub fn accept(&self, bytes: &[u8], now_ms: u64) -> Result<Offer, NoticeError> {
        let keys = self.trusted();
        let offer = self.store.offer(bytes, &self.policy(&keys, now_ms))?;
        if matches!(offer, Offer::Stored(_)) {
            *self.held.lock() = None;
        }
        Ok(offer)
    }

    /// The verdict on a notice received over gossip.
    pub fn judge(&self, bytes: &[u8], now_ms: u64) -> Judgement {
        match self.accept(bytes, now_ms) {
            Ok(Offer::Stored(n)) => Judgement::Forward(Box::new(n)),
            Ok(Offer::Known(_)) => Judgement::Drop,
            Err(NoticeError::Malformed(_) | NoticeError::BadSignature | NoticeError::NoKeys) => {
                Judgement::Reject
            }
            Err(_) => Judgement::Drop,
        }
    }

    fn held(&self, now_ms: u64) -> (Option<Vec<u8>>, Option<Notice>) {
        let mut slot = self.held.lock();
        if slot
            .as_ref()
            .is_none_or(|h| h.at.elapsed() >= CACHE_REFRESH)
        {
            let (notice, raw) = match self.current(now_ms) {
                Some((n, r)) => (Some(n), Some(r)),
                None => (None, None),
            };
            *slot = Some(Held {
                at: Instant::now(),
                raw,
                notice,
            });
        }
        let h = slot.as_ref().expect("filled above");
        (h.raw.clone(), h.notice.clone())
    }

    /// The answer to `tenzro_getUpdateNotice`: the signed notice for the caller
    /// to verify, an `etag` to ask again with (`if_none_match`), and how long
    /// the answer may be kept. Refused with [`RPC_ERR_RATE_LIMITED`] past the
    /// global limit. Reads only; nothing is written and nothing identifies the
    /// caller.
    pub fn rpc_reply(
        &self,
        params: Option<&Value>,
        epoch: Option<EpochView>,
        now_ms: u64,
    ) -> Result<Value, (i32, String)> {
        if let GcraDecision::Deny { retry_after } = self.limiter.check("rpc") {
            return Err((
                RPC_ERR_RATE_LIMITED,
                format!(
                    "tenzro_getUpdateNotice is answered at most every {} ms; retry in {} ms",
                    RPC_PERIOD.as_millis(),
                    retry_after.as_millis()
                ),
            ));
        }
        let (raw, notice) = self.held(now_ms);
        let etag = raw.as_ref().map(|r| hex::encode(Sha256::digest(r)));
        let asked = match params {
            Some(Value::Object(m)) => m.get("if_none_match").and_then(Value::as_str),
            Some(Value::Array(a)) => a
                .first()
                .and_then(|v| v.get("if_none_match"))
                .and_then(Value::as_str),
            _ => None,
        };
        let epoch_json =
            epoch.map(|e| json!({ "epoch": e.epoch, "blocks_to_boundary": e.blocks_to_boundary }));
        if etag.is_some() && asked == etag.as_deref() {
            return Ok(
                json!({ "unchanged": true, "etag": etag, "cache_ttl_secs": CACHE_TTL_SECS, "epoch": epoch_json }),
            );
        }
        let envelope: Option<Value> = raw.as_ref().and_then(|r| serde_json::from_slice(r).ok());
        Ok(json!({
            "notice": envelope,
            "etag": etag,
            "latest_version": notice.as_ref().map(|n| n.version.clone()),
            "severity": notice.as_ref().map(|n| n.severity.as_str()),
            "cache_ttl_secs": CACHE_TTL_SECS,
            "epoch": epoch_json,
        }))
    }
}

/// The gossip message carrying signed notice bytes.
pub fn message(signed: &[u8]) -> NetworkMessage {
    NetworkMessage::new(MessagePayload::Custom {
        topic: TOPIC.to_string(),
        data: signed.to_vec(),
    })
}

/// Judges every notice that arrives on [`TOPIC`]: the ticket is accepted (so
/// gossip passes the notice on) only for a newer, verified notice.
pub async fn serve_inbound(hub: Arc<NoticeHub>, mut held: mpsc::Receiver<ValidatedMessage>) {
    while let Some(ValidatedMessage { message, ticket }) = held.recv().await {
        let data = match message.payload {
            MessagePayload::Custom { data, .. } => data,
            _ => {
                ticket.reject();
                continue;
            }
        };
        let judge_hub = hub.clone();
        let verdict = tokio::task::spawn_blocking(move || judge_hub.judge(&data, now_ms()))
            .await
            .unwrap_or(Judgement::Drop);
        match verdict {
            Judgement::Forward(n) => {
                tracing::info!(version = %n.version, "newer release notice verified and passed on");
                ticket.accept();
                if hub.auto_install_armed() && hub.begin_auto_install(&n.version) {
                    schedule_auto_install(hub.clone(), *n);
                }
            }
            Judgement::Drop => ticket.ignore(),
            Judgement::Reject => ticket.reject(),
        }
    }
}

/// Starts the automatic install of `notice` at this machine's turn
/// ([`tenzro_update_notice::rollout::install_at_ms`]): at once for a
/// security release, otherwise after this machine's share of the stagger
/// window and inside the operator's install hours. The place taken by
/// [`NoticeHub::begin_auto_install`] is held while it waits, so a notice
/// heard again does not schedule a second install.
fn schedule_auto_install(hub: Arc<NoticeHub>, notice: Notice) {
    let prefs = tenzro_update_notice::banner::Prefs::load(&hub.data_dir);
    let machine = crate::identity_bootstrap::machine_did().unwrap_or_default();
    let now = now_ms();
    let at = tenzro_update_notice::rollout::install_at_ms(
        &notice,
        &machine,
        prefs.stagger_hours,
        prefs.install_hours,
        now,
    );
    let wait = Duration::from_millis(at.saturating_sub(now));
    if !wait.is_zero() {
        tracing::info!(
            version = %notice.version,
            in_secs = wait.as_secs(),
            "automatic install scheduled at this machine's turn"
        );
    }
    tokio::spawn(async move {
        tokio::time::sleep(wait).await;
        // The operator may have turned automatic installs off meanwhile.
        if hub.auto_install_armed() {
            if let Err(reason) = start_install(hub.clone(), notice.version, updater_beside_node()) {
                tracing::warn!(%reason, "automatic install not started");
                hub.end_install(None);
            }
        } else {
            hub.end_install(None);
        }
    });
}

/// Starts the install of the newest verified release at the operator's call
/// and answers with its version. Refused when this node knows of no release
/// newer than the one running, or while another install runs. `approved`
/// names the one release an approval covers: a newer one that became known
/// since is not installed on it. `updater` is the `tenzro` binary that
/// installs it ([`updater_beside_node`]).
pub fn install(
    hub: &Arc<NoticeHub>,
    now_ms: u64,
    approved: Option<&str>,
    updater: Option<PathBuf>,
) -> Result<String, String> {
    let version = hub
        .newer(now_ms)
        .ok_or("No release newer than the one running is known to this node.")?
        .version;
    if approved.is_some_and(|approved| approved != version) {
        return Err(format!(
            "Release {version} is now the newest this node knows of. Read the conditions again."
        ));
    }
    if !hub.begin_install() {
        return Err("An install is already running.".to_string());
    }
    start_install(hub.clone(), version.clone(), updater)?;
    Ok(version)
}

/// The `tenzro` binary beside the node's own, when there is one: the updater
/// an install runs.
pub fn updater_beside_node() -> Option<PathBuf> {
    let dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    Some(dir.join(if cfg!(windows) {
        "tenzro.exe"
    } else {
        "tenzro"
    }))
    .filter(|p| p.exists())
}

/// Runs the installed updater for a verified newer release, for an install
/// [`NoticeHub::begin_install`] admitted. It is the same flow as
/// `tenzro update run`: it stages the signed release and, only for a node that
/// serves no staked role, restarts it through its service and health-gates it,
/// rolling back a release that does not stay healthy. A node that serves a
/// staked role (a validator or provider) stages the release and is left for
/// its operator to restart at an epoch-safe moment, so an install never
/// restarts a validator on its own and never risks quorum. The installer reads
/// the node's role over RPC and fails closed to staging only when it cannot.
fn start_install(
    hub: Arc<NoticeHub>,
    version: String,
    updater: Option<PathBuf>,
) -> Result<(), String> {
    let Some(tenzro) = updater else {
        hub.end_install(None);
        return Err(
            "The tenzro updater was not found beside the node's binary, so nothing was installed."
                .to_string(),
        );
    };
    tracing::info!(%version, "staging the verified release (a staked node is not restarted on its own)");
    let spawned = std::process::Command::new(&tenzro)
        .args(["update", "run", "--yes"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    match spawned {
        // The installer is waited for off the runtime, so it is reaped and
        // a second one is not started beside it.
        Ok(mut child) => {
            std::thread::spawn(move || {
                if let Err(e) = child.wait() {
                    tracing::warn!(error = %e, "install: the updater could not be waited for");
                }
                hub.end_install(Some(&version));
            });
            Ok(())
        }
        Err(e) => {
            hub.end_install(None);
            Err(format!("The updater could not be started: {e}"))
        }
    }
}

static HUB: OnceLock<Arc<NoticeHub>> = OnceLock::new();

/// The release keys governance put on chain (SEC1 P-256), empty when it put
/// none. A node applies them at start and as each change enacts.
static GOVERNED_KEYS: parking_lot::RwLock<Vec<Vec<u8>>> = parking_lot::RwLock::new(Vec::new());

/// The keys notices verify under: the governed set when there is one, else
/// the node's own (the embedded release key or its trusted keys file).
fn effective_keys(own: &[Vec<u8>], governed: &[Vec<u8>]) -> Vec<Vec<u8>> {
    if governed.is_empty() {
        own.to_vec()
    } else {
        governed.to_vec()
    }
}

/// Replace the governed release keys with `keys_hex` (hex SEC1 P-256). An
/// entry that does not decode is skipped: the chain refused it at proposal.
pub fn set_governed_keys(keys_hex: &[String]) {
    *GOVERNED_KEYS.write() = keys_hex
        .iter()
        .filter_map(|k| hex::decode(k).ok())
        .collect();
}

/// Applies the release keys `chain` holds, once
/// `feature.update_notice_keys.activation_epoch` is in force.
pub fn apply_governed_keys(chain: &dyn tenzro_vm::VmState) {
    if tenzro_vm::feature_gate::is_live_now(
        chain,
        tenzro_vm::native::gateway_sets::UPDATE_NOTICE_KEYS_GATE,
    ) {
        set_governed_keys(&tenzro_vm::native::gateway_sets::update_notice_keys(chain));
    }
}

/// The node's hub, created on first use.
pub fn hub(data_dir: &Path) -> Arc<NoticeHub> {
    HUB.get_or_init(|| Arc::new(NoticeHub::for_node(data_dir)))
        .clone()
}

/// Reads `notice.json` from the downloads host. A plain GET: no identity, no
/// version, no query string.
async fn fetch(base: &str) -> Result<Vec<u8>, String> {
    let url = format!("{}/notice.json", base.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(40))
        .user_agent("tenzro")
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?;
    let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    if bytes.len() > notice::MAX_ENVELOPE_BYTES {
        return Err("larger than a notice may be".into());
    }
    Ok(bytes.to_vec())
}

/// Starts the notice tasks: gossip inbound, the fetch from the downloads host
/// and the periodic re-publish.
pub async fn start(network: Arc<TenzroNetworkService>, data_dir: PathBuf) {
    let hub = hub(&data_dir);
    match network.subscribe_validated(TOPIC).await {
        Ok(rx) => {
            tokio::spawn(serve_inbound(hub.clone(), rx));
        }
        Err(e) => tracing::warn!(error = %e, "could not join the release notice topic"),
    }
    let base = std::env::var("TENZRO_UPDATE_CHANNEL")
        .map(|c| tenzro_update_notice::rollout::channel_url(&c))
        .unwrap_or_else(|_| DEFAULT_CHANNEL_URL.to_string());
    let fetch_hub = hub.clone();
    let fetch_net = network.clone();
    tokio::spawn(async move {
        // The first ask waits a little so start-up work finishes first.
        tokio::time::sleep(Duration::from_secs(60)).await;
        loop {
            match fetch(&base).await {
                Ok(bytes) => match fetch_hub.accept(&bytes, now_ms()) {
                    Ok(Offer::Stored(n)) => {
                        tracing::info!(version = %n.version, "release notice fetched from the downloads host");
                        if let Err(e) = fetch_net.broadcast(TOPIC, message(&bytes)).await {
                            tracing::debug!(error = %e, "could not publish the fetched notice");
                        }
                    }
                    Ok(Offer::Known(_)) => {}
                    Err(e) => {
                        tracing::debug!(error = %e, "release notice from the downloads host not used")
                    }
                },
                Err(e) => tracing::debug!(error = %e, "release notice not fetched"),
            }
            tokio::time::sleep(FETCH_EVERY).await;
        }
    });
    tokio::spawn(async move {
        // A start offset spreads the nodes' re-publishing across the period.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0) as u64;
        tokio::time::sleep(Duration::from_secs(120 + nanos % REPUBLISH_EVERY.as_secs())).await;
        loop {
            if let Some((_, raw)) = hub.current(now_ms()) {
                let _ = network.broadcast(TOPIC, message(&raw)).await;
            }
            tokio::time::sleep(REPUBLISH_EVERY).await;
        }
    });
}

#[cfg(test)]
mod tests {

    #[test]
    fn governed_release_keys_replace_the_nodes_own_and_none_leaves_them() {
        let own = vec![vec![1u8, 2], vec![3]];
        assert_eq!(effective_keys(&own, &[]), own);
        let governed = vec![vec![9u8]];
        assert_eq!(effective_keys(&own, &governed), governed);
    }
    use super::*;
    use tenzro_update_notice::Severity;
    use tenzro_update_notice::notice::fixture::{NOW, key, notice, signed};

    fn hub_in(d: &Path) -> NoticeHub {
        NoticeHub::new(
            d,
            "stable",
            "0.2.1".parse().unwrap(),
            vec![key(1).public_sec1()],
        )
    }

    #[test]
    fn the_method_serves_the_newest_notice_and_answers_unchanged_to_its_etag() {
        let d = tempfile::tempdir().unwrap();
        let h = hub_in(d.path());
        let none = h.rpc_reply(None, None, NOW).unwrap();
        assert!(none["notice"].is_null() && none["etag"].is_null());
        let bytes = signed(&key(1), &notice("0.2.2", Severity::Security));
        assert!(matches!(h.accept(&bytes, NOW).unwrap(), Offer::Stored(_)));
        let got = h
            .rpc_reply(
                None,
                Some(EpochView {
                    epoch: 3,
                    blocks_to_boundary: Some(70),
                }),
                NOW,
            )
            .unwrap();
        assert_eq!(got["latest_version"], "0.2.2");
        assert_eq!(got["severity"], "security");
        assert_eq!(got["epoch"]["blocks_to_boundary"], 70);
        // The notice is served so the caller can verify it, byte for byte.
        let env = serde_json::to_vec(&got["notice"]).unwrap();
        let p = Policy {
            keys: &[key(1).public_sec1()],
            channel: "stable",
            running: "0.2.1".parse().unwrap(),
            now_ms: NOW,
        };
        assert_eq!(notice::verify(&env, &p).unwrap().version, "0.2.2");
        let etag = got["etag"].as_str().unwrap().to_string();
        let again = h
            .rpc_reply(Some(&json!({ "if_none_match": etag })), None, NOW)
            .unwrap();
        assert_eq!(again["unchanged"], true);
        assert!(again.get("notice").is_none());
    }

    #[test]
    fn a_held_notice_is_installable_only_when_it_is_newer_than_the_release_running() {
        let d = tempfile::tempdir().unwrap();
        let h = hub_in(d.path());
        assert!(h.newer(NOW).is_none());
        let bytes = signed(&key(1), &notice("0.2.2", Severity::Normal));
        assert!(matches!(h.accept(&bytes, NOW).unwrap(), Offer::Stored(_)));
        assert_eq!(h.newer(NOW).unwrap().version, "0.2.2");
        // The same notice, read by a node that already runs that release.
        let running_it = NoticeHub::new(
            d.path(),
            "stable",
            "0.2.2".parse().unwrap(),
            vec![key(1).public_sec1()],
        );
        assert!(running_it.newer(NOW).is_none());
    }

    #[test]
    fn the_method_is_rate_limited_past_its_burst() {
        let d = tempfile::tempdir().unwrap();
        let h = hub_in(d.path());
        let mut served = 0;
        let mut refused = None;
        for _ in 0..(RPC_BURST * 3) {
            match h.rpc_reply(None, None, NOW) {
                Ok(_) => served += 1,
                Err(e) => {
                    refused = Some(e);
                    break;
                }
            }
        }
        let (code, message) = refused.expect("the limit is reached");
        assert_eq!(code, RPC_ERR_RATE_LIMITED);
        assert!(message.contains("retry"), "{message}");
        assert!(
            served >= RPC_BURST as usize && served <= RPC_BURST as usize + 2,
            "{served}"
        );
    }

    #[test]
    fn gossip_judgement_forwards_only_newer_verified_notices() {
        let d = tempfile::tempdir().unwrap();
        let h = hub_in(d.path());
        let k = key(1);
        let v3 = signed(&k, &notice("0.2.9", Severity::Normal));
        assert!(matches!(h.judge(&v3, NOW), Judgement::Forward(_)));
        assert_eq!(h.judge(&v3, NOW), Judgement::Drop, "already held");
        assert_eq!(
            h.judge(&signed(&k, &notice("0.2.2", Severity::Normal)), NOW),
            Judgement::Drop,
            "older"
        );
        assert_eq!(
            h.judge(&signed(&key(2), &notice("0.2.9", Severity::Normal)), NOW),
            Judgement::Reject,
            "wrong key"
        );
        assert_eq!(h.judge(b"not json", NOW), Judgement::Reject);
        let mut other = notice("0.2.9", Severity::Normal);
        other.channel = "security".into();
        assert_eq!(
            h.judge(&signed(&k, &other), NOW),
            Judgement::Drop,
            "another channel is not blame"
        );
    }

    /// One install runs at a time, a release whose installer was started is
    /// not started again, and a start that failed is tried again.
    #[test]
    fn an_automatic_install_runs_once_a_release_and_one_at_a_time() {
        let d = tempfile::tempdir().unwrap();
        let hub = hub_in(d.path());
        assert!(hub.begin_auto_install("0.2.9"));
        assert!(!hub.begin_auto_install("0.2.4"), "one at a time");
        hub.end_install(None);
        assert!(hub.begin_auto_install("0.2.9"), "a failed start is retried");
        hub.end_install(Some("0.2.9"));
        assert!(!hub.begin_auto_install("0.2.9"), "started once a release");
        assert!(hub.begin_auto_install("0.2.4"));
    }

    /// The operator's install is refused with nothing newer to install, and
    /// a start that fails leaves the place free for the next one. A test
    /// binary has no updater beside it.
    #[test]
    fn an_install_the_operator_asks_for_names_why_it_did_not_start() {
        let d = tempfile::tempdir().unwrap();
        let hub = Arc::new(hub_in(d.path()));
        assert_eq!(
            install(&hub, NOW, None, None).unwrap_err(),
            "No release newer than the one running is known to this node."
        );

        let bytes = signed(&key(1), &notice("0.2.9", Severity::Normal));
        assert!(matches!(hub.accept(&bytes, NOW).unwrap(), Offer::Stored(_)));
        assert!(hub.begin_install());
        assert_eq!(
            install(&hub, NOW, None, None).unwrap_err(),
            "An install is already running."
        );
        hub.end_install(None);

        assert_eq!(
            install(&hub, NOW, None, None).unwrap_err(),
            "The tenzro updater was not found beside the node's binary, so nothing was installed."
        );
        assert!(hub.begin_install(), "a failed start frees the place");
    }

    #[test]
    fn an_approval_installs_only_the_release_it_names() {
        let d = tempfile::tempdir().unwrap();
        let hub = Arc::new(hub_in(d.path()));
        let bytes = signed(&key(1), &notice("0.2.9", Severity::Normal));
        assert!(matches!(hub.accept(&bytes, NOW).unwrap(), Offer::Stored(_)));

        assert_eq!(
            install(&hub, NOW, Some("0.2.2"), None).unwrap_err(),
            "Release 0.2.9 is now the newest this node knows of. Read the conditions again."
        );
        assert!(hub.begin_install(), "a refused approval takes no place");
        hub.end_install(None);

        // The named release is the newest: the install goes on to its start.
        assert_eq!(
            install(&hub, NOW, Some("0.2.9"), None).unwrap_err(),
            "The tenzro updater was not found beside the node's binary, so nothing was installed."
        );
    }
}
