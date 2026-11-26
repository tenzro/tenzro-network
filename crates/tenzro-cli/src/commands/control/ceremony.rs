//! Passkey ceremonies for the owner's apps.
//!
//! A ceremony here is the terminal's own: the session, the link, the callback
//! listener and the enrolment call `tenzro join` uses. The helper starts one,
//! hands the app the link and its QR code as rows of modules, and says where
//! it stands when asked. Binding and removing a device are ceremonies too,
//! held here and run by `devices`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde_json::{Value, json};

use super::{INVALID_PARAMS, REFUSED, error};
use crate::commands::join::{self, Joined};
use crate::onboarding::ceremony::{self, CeremonyError, Session};
use crate::rpc::RpcClient;

/// Where a ceremony stands.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum State {
    Waiting,
    Done,
    Failed,
    Expired,
}

impl State {
    fn word(self) -> &'static str {
        match self {
            State::Waiting => "waiting",
            State::Done => "done",
            State::Failed => "failed",
            State::Expired => "expired",
        }
    }
}

struct Entry {
    url: String,
    rows: Vec<String>,
    state: State,
    reason: Option<String>,
}

impl Entry {
    /// The ceremony as an app reads it. `qr` is the text to encode; no short
    /// code exists for a passkey enrolment, so `code` is null.
    fn answer(&self, id: &str) -> Value {
        json!({
            "id": id,
            "state": self.state.word(),
            "url": self.url,
            "qr": self.url,
            "qr_rows": self.rows,
            "code": null,
            "reason": self.reason,
        })
    }
}

#[derive(Default)]
struct Held {
    started: u64,
    all: HashMap<String, Entry>,
}

/// Keeps the identity a ceremony made, with the node it was made on.
type Keep = Box<dyn Fn(Joined, &str) -> anyhow::Result<()> + Send + Sync>;

/// How long the node has to enrol the passkey a ceremony made.
const ENROLMENT_WAIT: Duration = Duration::from_secs(30);

/// Why a ceremony failed whose passkey the node never answered for.
const NO_ENROLMENT_ANSWER: &str = "This machine's node did not answer the passkey enrolment. \
     The passkey was created but no identity exists yet.";

/// The ceremonies this helper started.
pub(crate) struct Ceremonies {
    node: String,
    wallet: String,
    /// Where a device is bound or removed: the node's own origin.
    pub(super) device_page: String,
    /// How long a page has to answer.
    pub(super) wait: Duration,
    node_wait: Duration,
    keep: Keep,
    held: Mutex<Held>,
}

impl Ceremonies {
    /// Ceremonies against the node at `node`, whose identities are kept in
    /// the CLI's configuration.
    pub(crate) fn here(node: &str) -> Arc<Self> {
        Arc::new(Self {
            node: node.to_string(),
            wallet: ceremony::wallet_url_from_env(),
            device_page: super::devices::page_from_env(),
            wait: ceremony::DEFAULT_TIMEOUT,
            node_wait: ENROLMENT_WAIT,
            keep: Box::new(|joined, node| {
                let mut cfg = crate::config::load_config();
                joined.keep(&mut cfg, node);
                crate::config::save_config(&cfg)
            }),
            held: Mutex::default(),
        })
    }

    /// Start a ceremony and answer with it, waiting. Ceremonies that ended
    /// are forgotten when a new one starts.
    pub(crate) async fn start(self: &Arc<Self>, params: &Value) -> Result<Value, Value> {
        match params.get("purpose").and_then(Value::as_str) {
            Some("enroll") => {}
            Some("bind" | "approve") => {
                return Err(error(
                    REFUSED,
                    "This call enrols a passkey: a device is bound with control_bindDevice, and no condition is approved here.",
                ));
            }
            Some(_) => {
                return Err(error(
                    INVALID_PARAMS,
                    "purpose is one of enroll, bind, approve",
                ));
            }
            None => return Err(error(INVALID_PARAMS, "purpose is needed")),
        }
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(join::DEFAULT_NAME)
            .trim_start_matches('@')
            .to_string();
        let origin =
            ceremony::origin_of(&self.wallet).map_err(|e| error(REFUSED, &e.to_string()))?;
        let session = Session::random();
        let (listener, port) = ceremony::bind()
            .await
            .map_err(|e| error(REFUSED, &e.to_string()))?;
        let url = ceremony::onboarding_url(&self.wallet, port, &session, &self.node, &name);
        let (id, answer) = self.hold(url)?;
        let this = self.clone();
        tokio::spawn(async move {
            let (state, reason) = this.finish(listener, &session, &origin, &name).await;
            this.settle(&id, state, reason);
        });
        Ok(answer)
    }

    /// Hold a new ceremony waiting on the page at `url`: its id, and the
    /// ceremony as an app reads it. Ceremonies that ended are forgotten.
    pub(super) fn hold(&self, url: String) -> Result<(String, Value), Value> {
        let rows = ceremony::qr_rows(&url).map_err(|e| error(REFUSED, &e.to_string()))?;
        let entry = Entry {
            url,
            rows,
            state: State::Waiting,
            reason: None,
        };
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        held.all.retain(|_, e| e.state == State::Waiting);
        held.started += 1;
        let id = format!("c{}", held.started);
        let answer = entry.answer(&id);
        held.all.insert(id.clone(), entry);
        Ok((id, answer))
    }

    /// Record how the ceremony `id` ended, and why.
    pub(super) fn settle(&self, id: &str, state: State, reason: Option<String>) {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = held.all.get_mut(id) {
            entry.state = state;
            entry.reason = reason;
        }
    }

    /// Where the ceremony `id` stands.
    pub(crate) fn status(&self, params: &Value) -> Result<Value, Value> {
        let id = params
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| error(INVALID_PARAMS, "id is needed"))?;
        let held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        held.all
            .get(id)
            .map(|entry| entry.answer(id))
            .ok_or_else(|| error(INVALID_PARAMS, "No such ceremony"))
    }

    /// Wait for the wallet page, enrol the passkey it made on the node and
    /// keep the identity. Returns how the ceremony ended and why.
    async fn finish(
        &self,
        listener: tokio::net::TcpListener,
        session: &Session,
        origin: &str,
        name: &str,
    ) -> (State, Option<String>) {
        let made = match ceremony::wait_for_callback(listener, session, origin, self.wait).await {
            Ok(made) => made,
            Err(CeremonyError::Timeout(_)) => return (State::Expired, None),
            Err(e) => return (State::Failed, Some(e.to_string())),
        };
        let node = RpcClient::only_at(&self.node);
        let enrolled = tokio::time::timeout(self.node_wait, join::enrol(&node, &made, name)).await;
        let enrolled = match enrolled {
            Ok(Ok(enrolled)) => enrolled,
            Ok(Err(e)) => return (State::Failed, Some(e.to_string().replace('\n', " "))),
            Err(_) => return (State::Failed, Some(NO_ENROLMENT_ANSWER.into())),
        };
        match (self.keep)(Joined::read(&enrolled, name), &self.node) {
            Ok(()) => (State::Done, None),
            Err(e) => (
                State::Failed,
                Some(format!(
                    "The identity was made but could not be kept on this machine: {e}"
                )),
            ),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::rpc::nonce_and_chain_id_tests::node_answering;

    /// Ceremonies against `node` that keep identities in `dir` and give the
    /// wallet page `wait` to answer.
    pub(crate) fn kept_in(node: &str, dir: &std::path::Path, wait: Duration) -> Arc<Ceremonies> {
        let dir = dir.to_path_buf();
        Arc::new(Ceremonies {
            node: node.to_string(),
            wallet: ceremony::DEFAULT_WALLET_URL.to_string(),
            // The test page answers from the wallet's origin, as the shared
            // test callback sends it.
            device_page: ceremony::DEFAULT_WALLET_URL.to_string(),
            wait,
            node_wait: Duration::from_secs(3),
            keep: Box::new(move |joined, node| {
                let mut cfg = crate::config::load_config_in(&dir);
                joined.keep(&mut cfg, node);
                crate::config::save_config_in(&dir, &cfg)
            }),
            held: Mutex::default(),
        })
    }

    fn query<'a>(url: &'a str, name: &str) -> &'a str {
        let (_, query) = url.split_once('?').unwrap();
        query
            .split('&')
            .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
            .unwrap()
    }

    /// Answer the ceremony at `url` as the wallet page does once a passkey
    /// was made.
    pub(crate) async fn approve(url: &str) {
        let session = Session {
            state: query(url, "state").to_string(),
            challenge: query(url, "challenge").to_string(),
        };
        let port: u16 = query(url, "callback")
            .strip_prefix("http%3A%2F%2F127.0.0.1%3A")
            .and_then(|rest| rest.strip_suffix("%2Fcallback"))
            .unwrap()
            .parse()
            .unwrap();
        let body = ceremony::tests::payload(&session, &session.state).to_string();
        let reply = ceremony::tests::post(port, &body, None).await;
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    }

    /// The ceremony `id` once it is no longer waiting.
    pub(crate) async fn ended(all: &Ceremonies, id: &str) -> Value {
        for _ in 0..500 {
            let now = all.status(&json!({ "id": id })).unwrap();
            if now["state"] != "waiting" {
                return now;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the ceremony {id} never ended");
    }

    const MINUTE: Duration = Duration::from_secs(60);

    /// A node that enrols whoever asks.
    pub(crate) const ENROLLED: &[(&str, &str)] = &[(
        "tenzro_onboardHuman",
        r#"{"identity":{"did":"did:tenzro:human:7","display_name":"Ada"},"wallet":{"wallet_id":"w-7","address":"0x07"}}"#,
    )];

    #[tokio::test]
    async fn a_ceremony_starts_waiting_with_its_link_and_its_code_as_rows() {
        let dir = tempfile::tempdir().unwrap();
        let all = kept_in("http://127.0.0.1:1", dir.path(), MINUTE);
        let started = all.start(&json!({ "purpose": "enroll" })).await.unwrap();

        assert_eq!(started["state"], "waiting");
        assert_eq!(started["reason"], Value::Null);
        assert_eq!(started["code"], Value::Null);
        let url = started["url"].as_str().unwrap();
        assert!(url.starts_with("https://wallet.tenzro.com/onboard?"));
        assert!(url.contains("name=Tenzro%20User"));
        assert!(url.contains("rpc=http%3A%2F%2F127.0.0.1%3A1"));
        assert_eq!(started["qr"], started["url"]);
        let rows = started["qr_rows"].as_array().unwrap();
        assert_eq!(
            rows.iter()
                .map(|r| r.as_str().unwrap().to_string())
                .collect::<Vec<_>>(),
            ceremony::qr_rows(url).unwrap()
        );
        assert_eq!(
            all.status(&json!({ "id": started["id"] })).unwrap(),
            started
        );
    }

    #[tokio::test]
    async fn an_approved_ceremony_enrols_on_the_node_and_keeps_the_identity() {
        let node = node_answering(ENROLLED).await;
        let dir = tempfile::tempdir().unwrap();
        let all = kept_in(&node, dir.path(), MINUTE);
        let started = all
            .start(&json!({ "purpose": "enroll", "name": "@Ada" }))
            .await
            .unwrap();
        assert!(started["url"].as_str().unwrap().ends_with("&name=Ada"));

        approve(started["url"].as_str().unwrap()).await;
        let end = ended(&all, started["id"].as_str().unwrap()).await;

        assert_eq!(end["state"], "done");
        assert_eq!(end["reason"], Value::Null);
        let cfg = crate::config::load_config_in(dir.path());
        assert_eq!(cfg.did.as_deref(), Some("did:tenzro:human:7"));
        assert_eq!(cfg.display_name.as_deref(), Some("Ada"));
        assert_eq!(cfg.wallet_id.as_deref(), Some("w-7"));
        assert_eq!(cfg.wallet_address.as_deref(), Some("0x07"));
        assert_eq!(cfg.endpoint.as_deref(), Some(node.as_str()));
    }

    #[tokio::test]
    async fn a_node_that_does_not_enrol_fails_the_ceremony_and_keeps_nothing() {
        let node = node_answering(&[]).await;
        let dir = tempfile::tempdir().unwrap();
        let all = kept_in(&node, dir.path(), MINUTE);
        let started = all.start(&json!({ "purpose": "enroll" })).await.unwrap();

        approve(started["url"].as_str().unwrap()).await;
        let end = ended(&all, started["id"].as_str().unwrap()).await;

        assert_eq!(end["state"], "failed");
        let reason = end["reason"].as_str().unwrap();
        assert!(reason.starts_with("The node refused the passkey enrolment: "));
        assert!(reason.ends_with("The passkey was created but no identity exists yet."));
        assert!(!reason.contains('\n'));
        assert_eq!(crate::config::load_config_in(dir.path()).did, None);
    }

    #[tokio::test]
    async fn a_node_that_never_answers_the_enrolment_fails_the_ceremony() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let node = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((call, _)) = listener.accept().await {
                held.push(call);
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let all = kept_in(&node, dir.path(), MINUTE);
        let started = all.start(&json!({ "purpose": "enroll" })).await.unwrap();

        approve(started["url"].as_str().unwrap()).await;
        let end = ended(&all, started["id"].as_str().unwrap()).await;

        assert_eq!(end["state"], "failed");
        assert_eq!(end["reason"], NO_ENROLMENT_ANSWER);
        assert_eq!(crate::config::load_config_in(dir.path()).did, None);
    }

    #[tokio::test]
    async fn a_ceremony_nobody_answers_runs_out() {
        let dir = tempfile::tempdir().unwrap();
        let all = kept_in("http://127.0.0.1:1", dir.path(), Duration::from_millis(50));
        let started = all.start(&json!({ "purpose": "enroll" })).await.unwrap();

        let end = ended(&all, started["id"].as_str().unwrap()).await;

        assert_eq!(end["state"], "expired");
        assert_eq!(end["reason"], Value::Null);
        assert_eq!(end["url"], started["url"]);
    }

    #[tokio::test]
    async fn a_new_ceremony_forgets_the_ones_that_ended() {
        let dir = tempfile::tempdir().unwrap();
        let all = kept_in("http://127.0.0.1:1", dir.path(), Duration::from_millis(50));
        let first = all.start(&json!({ "purpose": "enroll" })).await.unwrap();
        ended(&all, first["id"].as_str().unwrap()).await;

        let second = all.start(&json!({ "purpose": "enroll" })).await.unwrap();

        assert_ne!(first["id"], second["id"]);
        assert_eq!(
            all.status(&json!({ "id": first["id"] })).unwrap_err(),
            json!({ "code": -32602, "message": "No such ceremony" })
        );
        assert!(all.status(&json!({ "id": second["id"] })).is_ok());
    }

    #[tokio::test]
    async fn only_a_known_purpose_starts_a_ceremony() {
        let dir = tempfile::tempdir().unwrap();
        let all = kept_in("http://127.0.0.1:1", dir.path(), MINUTE);

        assert_eq!(
            all.start(&json!({})).await.unwrap_err(),
            json!({ "code": -32602, "message": "purpose is needed" })
        );
        assert_eq!(
            all.start(&json!({ "purpose": "sell" })).await.unwrap_err(),
            json!({ "code": -32602, "message": "purpose is one of enroll, bind, approve" })
        );
        for purpose in ["bind", "approve"] {
            let refused = all.start(&json!({ "purpose": purpose })).await.unwrap_err();
            assert_eq!(refused["code"], -32000);
        }
        assert_eq!(
            all.status(&json!({})).unwrap_err(),
            json!({ "code": -32602, "message": "id is needed" })
        );
    }
}
