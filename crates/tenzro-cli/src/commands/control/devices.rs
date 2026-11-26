//! `control_bindDevice` and `control_revokeDevice`: the devices whose
//! passkeys approve for the operator.
//!
//! The node checks a device's passkey against its own origin,
//! `https://<webauthn_rp_id>`, so the passkey is made or used on the device
//! page served there, not in the console on loopback. Each call asks the node
//! for a custody challenge, opens a ceremony on that page (a link and its QR
//! code, with a loopback callback, as a passkey enrolment does) and answers
//! `{state: "waiting", condition_id: null, ceremony}` at once;
//! `control_ceremonyStatus` says how it ended. When the page returns, the
//! node checks the registration (`tenzro_bindDevice`) or the assertion
//! (`tenzro_revokeBoundDevice`) against that challenge. A binding needs
//! `confirm: "bindDevice"` and a removal `confirm: "revokeDevice"`.
//!
//! # Contract with the device page
//!
//! The page is a separate repository. The helper opens `GET {page}/device`
//! with `mode` (`bind` or `revoke`), `state` (echoed back), `challenge` (the
//! node's `webauthn_challenge`, as it gave it), `callback`
//! (`http://127.0.0.1:{port}/callback`), and `label` for a binding or
//! `credential` (the credential id of the device to remove) for a removal.
//! The page answers `POST /callback` with JSON whose byte fields are
//! base64url:
//!
//! - `bind`: `state`, the new passkey's `attestation_object` and
//!   `client_data_json` over the challenge and, once the identity has a bound
//!   device, `authorization`;
//! - `revoke`: `state` and `authorization`.
//!
//! `authorization` is an assertion over the same challenge by a device
//! already bound: `credential_id` as the node lists it, `authenticator_data`,
//! `client_data_json` and `signature`. Before the node is asked, the helper
//! checks the state token and that each `clientDataJSON` is of the right type,
//! over the challenge, and made on the page's origin.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Value, json};

use super::ceremony::{Ceremonies, State};
use super::{Helper, INVALID_PARAMS, REFUSED, error};
use crate::onboarding::ceremony::{self as page, CeremonyError, Session, pct_encode};
use crate::rpc::RpcClient;

/// The node's own origin under the default `webauthn_rp_id`.
const DEFAULT_PAGE: &str = "https://tenzro.com";

/// Where devices are bound and removed: `TENZRO_DEVICE_PAGE_URL`, else the
/// node's origin under the default relying party.
pub(super) fn page_from_env() -> String {
    std::env::var("TENZRO_DEVICE_PAGE_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_PAGE.to_string())
}

/// What the page does with a device.
#[derive(Clone, Copy)]
enum Mode {
    Bind,
    Revoke,
}

impl Mode {
    fn word(self) -> &'static str {
        match self {
            Mode::Bind => "bind",
            Mode::Revoke => "revoke",
        }
    }

    /// The custody operation the node's challenge is for.
    fn operation(self) -> &'static str {
        match self {
            Mode::Bind => "bind_device",
            Mode::Revoke => "revoke_device",
        }
    }

    /// The node method that checks what the page returned.
    fn method(self) -> &'static str {
        match self {
            Mode::Bind => "tenzro_bindDevice",
            Mode::Revoke => "tenzro_revokeBoundDevice",
        }
    }
}

/// One device ceremony, from the node's challenge to the node's verdict.
struct Asked {
    mode: Mode,
    /// What the node is sent besides what the page returned.
    params: Value,
    /// The device's label, or the credential id of the device to remove.
    subject: String,
}

impl Helper {
    /// `control_bindDevice {label?, confirm}`.
    pub(super) async fn bind_device(&self, params: &Value) -> Result<Value, Value> {
        confirmed("bindDevice", params)?;
        let did = self.operator().await?;
        let label = params
            .get("label")
            .and_then(Value::as_str)
            .unwrap_or("New device")
            .to_string();
        let asked = Asked {
            mode: Mode::Bind,
            params: json!({ "identity_did": did, "label": label }),
            subject: label,
        };
        self.open_device_page(&did, asked).await
    }

    /// `control_revokeDevice {id, confirm}`.
    pub(super) async fn revoke_device(&self, params: &Value) -> Result<Value, Value> {
        confirmed("revokeDevice", params)?;
        let did = self.operator().await?;
        let id = params
            .get("id")
            .ok_or_else(|| error(INVALID_PARAMS, "id is needed"))?
            .as_str()
            .ok_or_else(|| error(INVALID_PARAMS, "id is the device's credential id"))?
            .to_string();
        let asked = Asked {
            mode: Mode::Revoke,
            params: json!({ "identity_did": did, "credential_id": id }),
            subject: id,
        };
        self.open_device_page(&did, asked).await
    }

    /// The operator's identity, which every device is bound to.
    async fn operator(&self) -> Result<String, Value> {
        (self.local)(false).await.did.ok_or_else(|| {
            error(
                REFUSED,
                "This machine has no operator identity yet: finish setup first",
            )
        })
    }

    /// Ask the node for the challenge, open the device page on it and answer
    /// with the ceremony, which ends once the node has checked the page's
    /// result.
    async fn open_device_page(&self, did: &str, mut asked: Asked) -> Result<Value, Value> {
        let all = self.ceremonies.clone();
        let origin =
            page::origin_of(&all.device_page).map_err(|e| error(REFUSED, &e.to_string()))?;
        let issued = self
            .node_call(
                "tenzro_createCustodyChallenge",
                json!({
                    "account_address": hex::encode(did.as_bytes()),
                    "operation": asked.mode.operation(),
                    "target_hex": hex::encode(asked.subject.as_bytes()),
                }),
            )
            .await?;
        let (Some(challenge_id), Some(challenge)) = (
            issued.get("challenge_id").cloned(),
            issued.get("webauthn_challenge").and_then(Value::as_str),
        ) else {
            return Err(error(
                REFUSED,
                "This machine's node gave no custody challenge.",
            ));
        };
        asked.params["challenge_id"] = challenge_id;
        let session = Session {
            state: Session::random().state,
            challenge: challenge.to_string(),
        };
        let (listener, port) = page::bind()
            .await
            .map_err(|e| error(REFUSED, &e.to_string()))?;
        let (id, ceremony) = all.hold(page_url(&all.device_page, port, &session, &asked))?;
        let node = RpcClient::only_at(self.node.url());
        let node_wait = self.node_wait;
        tokio::spawn(async move {
            let (state, reason) =
                finish(&all, listener, &session, &origin, asked, &node, node_wait).await;
            all.settle(&id, state, reason);
        });
        Ok(json!({ "state": "waiting", "condition_id": null, "ceremony": ceremony }))
    }

    /// One call to the node: its result, or its refusal as it gave it.
    pub(super) async fn node_call(&self, method: &str, params: Value) -> Result<Value, Value> {
        match self.ask_node(method, params, self.node_has_until()).await {
            Some(answer) => answer,
            None => Err(error(REFUSED, "This machine's node is not answering.")),
        }
    }
}

/// The device page for one ceremony.
fn page_url(page: &str, port: u16, session: &Session, asked: &Asked) -> String {
    let subject = match asked.mode {
        Mode::Bind => "label",
        Mode::Revoke => "credential",
    };
    format!(
        "{}/device?mode={}&state={}&challenge={}&callback={}&{subject}={}",
        page.trim_end_matches('/'),
        asked.mode.word(),
        pct_encode(&session.state),
        pct_encode(&session.challenge),
        pct_encode(&format!("http://127.0.0.1:{port}/callback")),
        pct_encode(&asked.subject),
    )
}

/// Wait for the page, then have the node check what it returned. Returns how
/// the ceremony ended and why.
async fn finish(
    all: &Ceremonies,
    listener: tokio::net::TcpListener,
    session: &Session,
    origin: &str,
    asked: Asked,
    node: &RpcClient,
    node_wait: Duration,
) -> (State, Option<String>) {
    let check = |body: &[u8]| returned(body, asked.mode, session, origin);
    let returned = match page::wait_for_page(listener, origin, all.wait, &check).await {
        Ok(returned) => returned,
        Err(CeremonyError::Timeout(_)) => return (State::Expired, None),
        Err(e) => return (State::Failed, Some(e.to_string())),
    };
    let mut params = asked.params;
    for (field, value) in returned {
        params[field] = value;
    }
    match tokio::time::timeout(node_wait, node.forward(asked.mode.method(), params)).await {
        Ok(Ok(Ok(_))) => (State::Done, None),
        Ok(Ok(Err(refused))) => (
            State::Failed,
            refused
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_string),
        ),
        Ok(Err(_)) | Err(_) => (
            State::Failed,
            Some("This machine's node did not answer.".to_string()),
        ),
    }
}

/// What the page returned, as the node's fields, once it is this ceremony's.
fn returned(
    body: &[u8],
    mode: Mode,
    session: &Session,
    origin: &str,
) -> Result<Vec<(&'static str, Value)>, (u16, String)> {
    let body: Value = serde_json::from_slice(body)
        .map_err(|e| (400u16, format!("the callback body is not JSON: {e}")))?;
    let state = body
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !page::constant_time_eq(state.as_bytes(), session.state.as_bytes()) {
        return Err((
            403,
            "the state token does not match this ceremony".to_string(),
        ));
    }
    let mut fields = Vec::new();
    if let Mode::Bind = mode {
        let client = bytes(&body, "client_data_json")?;
        made_here(&client, "webauthn.create", session, origin)?;
        fields.push((
            "attestation_object_b64",
            STANDARD.encode(bytes(&body, "attestation_object")?).into(),
        ));
        fields.push(("client_data_json_b64", STANDARD.encode(client).into()));
    }
    match (body.get("authorization"), mode) {
        (Some(by), _) => fields.push(("authorization", assertion(by, session, origin)?)),
        (None, Mode::Revoke) => return Err((400u16, "authorization is needed".to_string())),
        (None, Mode::Bind) => {}
    }
    Ok(fields)
}

/// An assertion by a bound device, as the node takes it.
fn assertion(by: &Value, session: &Session, origin: &str) -> Result<Value, (u16, String)> {
    let credential_id = by
        .get("credential_id")
        .and_then(Value::as_str)
        .ok_or_else(|| (400u16, "authorization.credential_id is needed".to_string()))?;
    let client = bytes(by, "client_data_json")?;
    made_here(&client, "webauthn.get", session, origin)?;
    Ok(json!({
        "credential_id": credential_id,
        "authenticator_data_b64": STANDARD.encode(bytes(by, "authenticator_data")?),
        "client_data_json_b64": STANDARD.encode(client),
        "signature_b64": STANDARD.encode(bytes(by, "signature")?),
    }))
}

/// The bytes of the base64url field `name`.
fn bytes(from: &Value, name: &str) -> Result<Vec<u8>, (u16, String)> {
    let text = from
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| (400u16, format!("{name} is needed")))?;
    URL_SAFE_NO_PAD
        .decode(text.trim_end_matches('='))
        .map_err(|e| (400u16, format!("{name} is not base64url: {e}")))
}

/// Whether a `clientDataJSON` is a `kind` ceremony over this challenge, made
/// on the page's origin.
fn made_here(
    client: &[u8],
    kind: &str,
    session: &Session,
    origin: &str,
) -> Result<(), (u16, String)> {
    let client: Value = serde_json::from_slice(client)
        .map_err(|e| (400u16, format!("client_data_json is not JSON: {e}")))?;
    let wrong = if client["type"] != kind {
        format!("client_data_json is not a {kind} ceremony")
    } else if client["challenge"] != session.challenge.as_str() {
        "client_data_json answers a different challenge".to_string()
    } else if client["origin"] != origin {
        "client_data_json was made on another origin".to_string()
    } else {
        return Ok(());
    };
    Err((400u16, wrong))
}

fn confirmed(name: &str, params: &Value) -> Result<(), Value> {
    if params.get("confirm").and_then(Value::as_str) == Some(name) {
        Ok(())
    } else {
        Err(error(
            REFUSED,
            &format!(
                "This changes which devices approve for the operator: send it again with confirm set to \"{name}\""
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{helper, helper_holding, machine};
    use super::*;
    use crate::onboarding::ceremony::tests::post;
    use crate::rpc::nonce_and_chain_id_tests::node_answering;

    const CHALLENGE: &str =
        r#"{"challenge_id":"ch-1","webauthn_challenge":"q83v","expires_in_secs":300}"#;
    const ORIGIN: &str = "https://wallet.tenzro.com";

    async fn ask(helper: &Helper, method: &str, params: Value) -> Value {
        let line = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let answer = helper.answer(line.to_string().as_bytes()).await.unwrap();
        serde_json::from_str(&answer).unwrap()
    }

    fn query<'a>(url: &'a str, name: &str) -> &'a str {
        let (_, query) = url.split_once('?').unwrap();
        query
            .split('&')
            .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
            .unwrap()
    }

    fn port(url: &str) -> u16 {
        query(url, "callback")
            .strip_prefix("http%3A%2F%2F127.0.0.1%3A")
            .and_then(|rest| rest.strip_suffix("%2Fcallback"))
            .unwrap()
            .parse()
            .unwrap()
    }

    fn client(kind: &str, challenge: &str) -> String {
        URL_SAFE_NO_PAD
            .encode(json!({ "type": kind, "challenge": challenge, "origin": ORIGIN }).to_string())
    }

    fn signed_by(credential: &str) -> Value {
        json!({
            "credential_id": credential,
            "authenticator_data": URL_SAFE_NO_PAD.encode(b"a"),
            "client_data_json": client("webauthn.get", "q83v"),
            "signature": URL_SAFE_NO_PAD.encode(b"s"),
        })
    }

    /// The ceremony `id` once it is no longer waiting.
    async fn ended(helper: &Helper, id: &Value) -> Value {
        for _ in 0..500 {
            let now = ask(helper, "control_ceremonyStatus", json!({ "id": id })).await;
            if now["result"]["state"] != "waiting" {
                return now["result"].clone();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the ceremony {id} never ended");
    }

    #[tokio::test]
    async fn binding_opens_the_device_page_and_the_node_checks_what_it_made() {
        let node = node_answering(&[
            ("tenzro_createCustodyChallenge", CHALLENGE),
            ("tenzro_bindDevice", r#"{"credential_id":"c9"}"#),
        ])
        .await;
        let helper = helper_holding(&node, Duration::from_secs(60));
        let params = json!({ "label": "Phone", "confirm": "bindDevice" });
        let opened = ask(&helper, "control_bindDevice", params).await;
        let opened = &opened["result"];
        assert_eq!(opened["state"], "waiting");
        assert_eq!(opened["condition_id"], Value::Null);
        let ceremony = &opened["ceremony"];
        assert_eq!(ceremony["state"], "waiting");
        let url = ceremony["url"].as_str().unwrap();
        assert!(
            url.starts_with(&format!("{ORIGIN}/device?mode=bind&")),
            "{url}"
        );
        assert_eq!(query(url, "challenge"), "q83v");
        assert_eq!(query(url, "label"), "Phone");

        // A registration over another challenge is refused and the ceremony
        // goes on waiting.
        let state = query(url, "state");
        let stray = json!({
            "state": state,
            "attestation_object": URL_SAFE_NO_PAD.encode(b"o"),
            "client_data_json": client("webauthn.create", "other"),
        });
        let reply = post(port(url), &stray.to_string(), None).await;
        assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");

        let made = json!({
            "state": state,
            "attestation_object": URL_SAFE_NO_PAD.encode(b"o"),
            "client_data_json": client("webauthn.create", "q83v"),
            "authorization": signed_by("c1"),
        });
        let reply = post(port(url), &made.to_string(), None).await;
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
        let end = ended(&helper, &ceremony["id"]).await;
        assert_eq!(end["state"], "done", "{end}");
    }

    #[tokio::test]
    async fn removing_a_device_needs_a_bound_devices_assertion() {
        let node = node_answering(&[
            ("tenzro_createCustodyChallenge", CHALLENGE),
            ("tenzro_revokeBoundDevice", r#"{"revoked":true}"#),
        ])
        .await;
        let helper = helper_holding(&node, Duration::from_secs(60));
        let unconfirmed = ask(&helper, "control_revokeDevice", json!({ "id": "c9" })).await;
        assert_eq!(unconfirmed["error"]["code"], REFUSED);
        let params = json!({ "confirm": "revokeDevice" });
        let nameless = ask(&helper, "control_revokeDevice", params).await;
        assert_eq!(nameless["error"]["code"], INVALID_PARAMS);

        let params = json!({ "id": "c9", "confirm": "revokeDevice" });
        let opened = ask(&helper, "control_revokeDevice", params).await;
        let opened = &opened["result"];
        let url = opened["ceremony"]["url"].as_str().unwrap();
        assert!(url.contains("/device?mode=revoke&"), "{url}");
        assert_eq!(query(url, "credential"), "c9");
        let state = query(url, "state");
        let unsigned = json!({ "state": state });
        let reply = post(port(url), &unsigned.to_string(), None).await;
        assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");
        let signed = json!({ "state": state, "authorization": signed_by("c1") });
        let reply = post(port(url), &signed.to_string(), None).await;
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
        let end = ended(&helper, &opened["ceremony"]["id"]).await;
        assert_eq!(end["state"], "done", "{end}");
    }

    #[tokio::test]
    async fn a_node_that_refuses_the_device_fails_the_ceremony_with_its_reason() {
        let node = node_answering(&[("tenzro_createCustodyChallenge", CHALLENGE)]).await;
        let helper = helper_holding(&node, Duration::from_secs(60));
        let params = json!({ "id": "c9", "confirm": "revokeDevice" });
        let opened = ask(&helper, "control_revokeDevice", params).await;
        let opened = &opened["result"];
        let url = opened["ceremony"]["url"].as_str().unwrap();
        let signed = json!({ "state": query(url, "state"), "authorization": signed_by("c1") });
        let reply = post(port(url), &signed.to_string(), None).await;
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
        let end = ended(&helper, &opened["ceremony"]["id"]).await;
        assert_eq!(end["state"], "failed");
        assert!(end["reason"].is_string(), "{end}");
    }

    #[tokio::test]
    async fn without_an_operator_identity_no_device_is_bound() {
        let mut local = machine();
        local.did = None;
        let helper = helper("http://127.0.0.1:1", local);
        let params = json!({ "confirm": "bindDevice" });
        let answer = ask(&helper, "control_bindDevice", params).await;
        assert_eq!(answer["error"]["code"], REFUSED);
    }
}
