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

/// Where the downloads host publishes the channel, unless `TENZRO_UPDATE_CHANNEL` says otherwise.
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
        }
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

    fn policy(&self, now_ms: u64) -> Policy<'_> {
        Policy {
            keys: &self.keys,
            channel: &self.channel,
            running: self.running,
            now_ms,
        }
    }

    /// The newest verified notice and its signed bytes.
    pub fn current(&self, now_ms: u64) -> Option<(Notice, Vec<u8>)> {
        self.store.cached(&self.policy(now_ms))
    }

    /// Verifies `bytes`; keeps them if they are newer than what is held.
    pub fn accept(&self, bytes: &[u8], now_ms: u64) -> Result<Offer, NoticeError> {
        let offer = self.store.offer(bytes, &self.policy(now_ms))?;
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
        let hub = hub.clone();
        let verdict = tokio::task::spawn_blocking(move || hub.judge(&data, now_ms()))
            .await
            .unwrap_or(Judgement::Drop);
        match verdict {
            Judgement::Forward(n) => {
                tracing::info!(version = %n.version, "newer release notice verified and passed on");
                ticket.accept();
            }
            Judgement::Drop => ticket.ignore(),
            Judgement::Reject => ticket.reject(),
        }
    }
}

static HUB: OnceLock<Arc<NoticeHub>> = OnceLock::new();

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
    let base =
        std::env::var("TENZRO_UPDATE_CHANNEL").unwrap_or_else(|_| DEFAULT_CHANNEL_URL.to_string());
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
        let v3 = signed(&k, &notice("0.2.3", Severity::Normal));
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
}
