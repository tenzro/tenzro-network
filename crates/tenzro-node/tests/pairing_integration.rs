//! Device pairing end to end over a live RPC server: an administrator starts
//! a pairing, a device signed in with its own key redeems the code, makes the
//! calls a paired device may make and no other admin call, and is unpaired.
//! A device signs in on the strength of the code alone for a token that only
//! redeems it, and wrong codes cancel the pairing they name.

mod dpop_bearer;
mod passkey_holder;

use std::sync::Arc;

use serde_json::{Value, json};
use tokio::sync::broadcast;

use tenzro_node::{NodeConfig, RpcServer, TenzroNode};

use dpop_bearer::{Bearer, OperatorKey};

struct TestNode {
    url: String,
    tx: broadcast::Sender<()>,
    handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
    tmp: tempfile::TempDir,
    client: reqwest::Client,
}

impl TestNode {
    async fn start(operator: &OperatorKey) -> Self {
        Self::start_as(operator, false).await
    }

    /// A node that also runs the paired-device listener, on a loopback port
    /// of its own.
    #[cfg(feature = "paired-devices")]
    async fn start_with_listener(operator: &OperatorKey) -> Self {
        Self::start_as(operator, true).await
    }

    async fn start_as(operator: &OperatorKey, listener: bool) -> Self {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cfg = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            iroh: tenzro_iroh::TenzroIrohConfig::loopback(),
            operator_did: Some(operator.did()),
            paired_device_addr: "127.0.0.1:0".to_string(),
            ..Default::default()
        };
        let mut node = TenzroNode::new(cfg).await.expect("node creation");
        node.start().await.expect("node start");
        let node = Arc::new(node);
        node.bind_self();
        let (tx, rx) = broadcast::channel::<()>(1);
        #[cfg(not(feature = "paired-devices"))]
        let _ = listener;
        #[cfg(feature = "paired-devices")]
        if listener {
            tokio::spawn(tenzro_node::paired_listener::run(
                node.clone(),
                tx.subscribe(),
            ));
        }
        let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
        let rpc = RpcServer::new(node, "127.0.0.1:0".to_string());
        let handle =
            tokio::spawn(async move { rpc.start_with_shutdown_and_addr(rx, addr_tx).await });
        let addr = addr_rx.await.expect("bound address");
        Self {
            url: format!("http://{addr}"),
            tx,
            handle,
            tmp,
            client: reqwest::Client::new(),
        }
    }

    async fn call(&self, method: &str, params: Value) -> Value {
        self.client
            .post(&self.url)
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
            .send()
            .await
            .expect("HTTP")
            .json()
            .await
            .expect("JSON")
    }

    async fn call_as(&self, who: &Bearer, method: &str, params: Value) -> Value {
        who.call(&self.client, &self.url, method, params).await
    }

    /// An administrator starts a pairing; the code a device types.
    async fn start_pairing(&self, admin: &Bearer) -> (String, String) {
        let resp = self.call_as(admin, "tenzro_pairDevice", json!({})).await;
        let started = &resp["result"];
        assert_eq!(started["state"], "waiting", "{resp}");
        (
            started["id"].as_str().expect("id").to_string(),
            started["code"].as_str().expect("code").to_string(),
        )
    }

    /// A device with its own key signs in and redeems `code`.
    async fn pair(&self, admin: &Bearer, label: &str, kind: &str) -> (String, Bearer) {
        let (_, code) = self.start_pairing(admin).await;
        let key = OperatorKey::new();
        let device = key.sign_in(&self.client, &self.url).await;
        let resp = self
            .call_as(
                &device,
                "tenzro_pairDevice",
                json!({ "secret": code, "label": label, "kind": kind }),
            )
            .await;
        assert_eq!(resp["result"]["device"]["id"], key.did(), "{resp}");
        (key.did(), device)
    }

    /// What an administrator reads of pairing `id`.
    async fn pairing(&self, admin: &Bearer, id: &str) -> Value {
        let resp = self
            .call_as(admin, "tenzro_pairDevice", json!({ "id": id }))
            .await;
        assert!(resp["result"].is_object(), "{resp}");
        resp["result"].clone()
    }

    /// The node's answer to `key` signing in with a code it refuses.
    async fn refused_sign_in(&self, key: &OperatorKey, code: &str) -> Value {
        match key.sign_in_with(&self.client, &self.url, Some(code)).await {
            Ok((_, issued)) => panic!("signed in: {issued}"),
            Err(resp) => resp,
        }
    }

    fn policy_file(&self) -> String {
        std::fs::read_to_string(self.tmp.path().join("access.toml")).expect("access.toml")
    }

    async fn stop(self) {
        let _ = self.tx.send(());
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), self.handle).await;
    }
}

/// `code` with another character in `at`: the last one keeps the pairing the
/// code names and misses its secret, the first one names another pairing.
fn miscopied(code: &str, at: usize) -> String {
    let other = if code.as_bytes()[at] == b'0' {
        "1"
    } else {
        "0"
    };
    format!("{}{other}{}", &code[..at], &code[at + 1..])
}

fn wrong_secret(code: &str) -> String {
    miscopied(code, code.len() - 1)
}

#[tokio::test]
async fn an_administrator_starts_a_pairing_and_a_device_redeems_it_once() {
    let operator = OperatorKey::new();
    let n = TestNode::start(&operator).await;
    let op = operator.sign_in(&n.client, &n.url).await;

    // Only an administrator starts a pairing.
    let resp = n.call("tenzro_pairDevice", json!({})).await;
    assert_eq!(resp["error"]["code"], -32004, "{resp}");
    let stranger = OperatorKey::new().sign_in(&n.client, &n.url).await;
    let resp = n.call_as(&stranger, "tenzro_pairDevice", json!({})).await;
    assert_eq!(resp["error"]["code"], -32004, "{resp}");

    let resp = n.call_as(&op, "tenzro_pairDevice", json!({})).await;
    let started = &resp["result"];
    assert_eq!(started["state"], "waiting", "{resp}");
    assert_eq!(started["reason"], "", "{resp}");
    assert_eq!(started["expires_in_secs"], 300, "{resp}");
    let id = started["id"].as_str().expect("id").to_string();
    let code = started["code"].as_str().expect("code").to_string();
    assert_eq!(code.len(), 24, "five groups of four with dashes: {code}");
    let url = started["url"].as_str().expect("url");
    assert!(url.starts_with("https://control.tenzro.com/pair#"), "{url}");
    let node_did = started["node_did"].as_str().expect("node did");
    assert!(node_did.starts_with("did:tenzro:machine:"), "{resp}");
    assert!(
        url.contains(&format!("did={}&", urlencoding::encode(node_did))),
        "{url}"
    );
    assert!(
        url.ends_with(&format!("secret={}", code.replace('-', ""))),
        "{url}"
    );
    assert_eq!(started["qr"], started["url"], "{resp}");
    let rows = started["qr_rows"].as_array().expect("qr_rows");
    assert!(rows.len() >= 21, "{resp}");
    for row in rows {
        let row = row.as_str().expect("row");
        assert_eq!(row.len(), rows.len(), "the code is square");
        assert!(row.bytes().all(|b| b == b'0' || b == b'1'), "{row}");
    }

    // The pairing waits, and its status repeats neither the code nor the QR.
    let resp = n
        .call_as(&op, "tenzro_pairDevice", json!({ "id": id }))
        .await;
    assert_eq!(resp["result"]["state"], "waiting", "{resp}");
    assert!(resp["result"].get("code").is_none(), "{resp}");
    assert!(resp["result"].get("url").is_none(), "{resp}");
    let resp = n
        .call_as(&stranger, "tenzro_pairDevice", json!({ "id": id }))
        .await;
    assert_eq!(resp["error"]["code"], -32004, "{resp}");
    let resp = n
        .call_as(&op, "tenzro_pairDevice", json!({ "id": "0000" }))
        .await;
    assert_eq!(resp["error"]["code"], -32602, "{resp}");

    // A code is redeemed by a signed-in device, never by the operator and
    // never anonymously; a wrong code opens nothing.
    let redeem = json!({ "secret": code, "label": "Hall phone", "kind": "phone" });
    let resp = n.call("tenzro_pairDevice", redeem.clone()).await;
    assert_eq!(resp["error"]["code"], -32004, "{resp}");
    let resp = n.call_as(&op, "tenzro_pairDevice", redeem.clone()).await;
    assert_eq!(resp["error"]["code"], -32602, "{resp}");
    let phone_key = OperatorKey::new();
    let phone = phone_key.sign_in(&n.client, &n.url).await;
    for wrong in [wrong_secret(&code), "0000-0000-0000-0000".to_string()] {
        let wrong = json!({ "secret": wrong, "label": "Hall phone", "kind": "phone" });
        let resp = n.call_as(&phone, "tenzro_pairDevice", wrong).await;
        assert_eq!(resp["error"]["code"], -32602, "{resp}");
    }
    let unknown_kind = json!({ "secret": code, "label": "Hall phone", "kind": "fridge" });
    let resp = n.call_as(&phone, "tenzro_pairDevice", unknown_kind).await;
    assert_eq!(resp["error"]["code"], -32602, "{resp}");

    // The code as a person types it: lower case, spaces for dashes.
    let typed = code.to_lowercase().replace('-', " ");
    let resp = n
        .call_as(
            &phone,
            "tenzro_pairDevice",
            json!({ "secret": typed, "label": "Hall phone", "kind": "phone" }),
        )
        .await;
    let paired = &resp["result"];
    assert_eq!(paired["device"]["id"], phone_key.did(), "{resp}");
    assert_eq!(paired["device"]["label"], "Hall phone", "{resp}");
    assert_eq!(paired["device"]["kind"], "phone", "{resp}");
    assert_eq!(
        paired["device"]["signed_in_with"], "hardware key, or passkey with its post-quantum leg",
        "{resp}"
    );
    assert_eq!(
        paired["methods"],
        json!([
            "tenzro_approveDeviceCode",
            "tenzro_installUpdate",
            "tenzro_listConditions",
            "tenzro_listPairedDevices",
            "tenzro_restartNode",
            "tenzro_submitApproval",
            "tenzro_unpairDevice",
        ]),
        "{resp}"
    );

    let resp = n
        .call_as(&op, "tenzro_pairDevice", json!({ "id": id }))
        .await;
    assert_eq!(resp["result"]["state"], "done", "{resp}");
    assert_eq!(resp["result"]["device"]["id"], phone_key.did(), "{resp}");

    // The code worked once.
    let second = OperatorKey::new().sign_in(&n.client, &n.url).await;
    let resp = n.call_as(&second, "tenzro_pairDevice", redeem).await;
    assert_eq!(resp["error"]["code"], -32602, "{resp}");
    n.stop().await;
}

#[tokio::test]
async fn a_paired_device_makes_the_paired_calls_and_no_other_admin_call() {
    let operator = OperatorKey::new();
    let n = TestNode::start(&operator).await;
    let op = operator.sign_in(&n.client, &n.url).await;
    let (phone_did, phone) = n.pair(&op, "Hall phone", "phone").await;
    let (tv_did, tv) = n.pair(&op, "Kitchen TV", "tv").await;

    // The access policy names each device for the paired calls.
    let resp = n.call_as(&op, "tenzro_getAccessPolicy", json!({})).await;
    assert_eq!(resp["result"]["policy"]["version"], 2, "{resp}");
    let file = n.policy_file();
    for resource in ["rpc:tenzro_listPairedDevices", "rpc:tenzro_unpairDevice"] {
        assert!(file.contains(resource), "{file}");
    }
    assert!(
        file.contains(&phone_did) && file.contains(&tv_did),
        "{file}"
    );

    // Each device reads the list and finds itself in it.
    for (who, did) in [(&phone, &phone_did), (&tv, &tv_did)] {
        let resp = n.call_as(who, "tenzro_listPairedDevices", json!({})).await;
        let devices = resp["result"]["devices"].as_array().expect("devices");
        assert_eq!(devices.len(), 2, "{resp}");
        for device in devices {
            assert_eq!(device["this_device"], device["id"] == **did, "{resp}");
        }
    }
    let resp = n.call_as(&op, "tenzro_listPairedDevices", json!({})).await;
    let devices = resp["result"]["devices"].as_array().expect("devices");
    assert_eq!(devices.len(), 2, "{resp}");
    assert!(devices.iter().all(|d| d["this_device"] == false), "{resp}");

    // Nobody else reads it.
    let stranger = OperatorKey::new().sign_in(&n.client, &n.url).await;
    let resp = n
        .call_as(&stranger, "tenzro_listPairedDevices", json!({}))
        .await;
    assert_eq!(resp["error"]["code"], -32004, "{resp}");
    let resp = n.call("tenzro_listPairedDevices", json!({})).await;
    assert_eq!(resp["error"]["code"], -32004, "{resp}");

    // Pairing opens the paired calls and nothing else an administrator does:
    // a paired device reads no policy, writes none, and pairs no device.
    for (method, params) in [
        ("tenzro_getAccessPolicy", json!({})),
        ("tenzro_listAccessTokens", json!({})),
        ("tenzro_listAdminAudit", json!({})),
        ("tenzro_pairDevice", json!({})),
    ] {
        let resp = n.call_as(&phone, method, params).await;
        assert_eq!(resp["error"]["code"], -32004, "{method}: {resp}");
    }
    n.stop().await;
}

#[tokio::test]
async fn unpairing_ends_a_devices_access() {
    let operator = OperatorKey::new();
    let n = TestNode::start(&operator).await;
    let op = operator.sign_in(&n.client, &n.url).await;
    let (phone_did, phone) = n.pair(&op, "Hall phone", "phone").await;
    let (tv_did, tv) = n.pair(&op, "Kitchen TV", "tv").await;

    // A paired device removes itself and no other device.
    let resp = n
        .call_as(&phone, "tenzro_unpairDevice", json!({ "id": tv_did }))
        .await;
    assert_eq!(resp["error"]["code"], -32004, "{resp}");
    let resp = n
        .call_as(&phone, "tenzro_unpairDevice", json!({ "id": phone_did }))
        .await;
    assert_eq!(resp["result"]["unpaired"], phone_did, "{resp}");

    // Its token is still good and opens nothing a paired device had.
    let resp = n
        .call_as(&phone, "tenzro_listPairedDevices", json!({}))
        .await;
    assert_eq!(resp["error"]["code"], -32004, "{resp}");
    let resp = n
        .call_as(&phone, "tenzro_unpairDevice", json!({ "id": tv_did }))
        .await;
    assert_eq!(resp["error"]["code"], -32004, "{resp}");
    let file = n.policy_file();
    assert!(!file.contains(&phone_did), "{file}");
    assert!(file.contains(&tv_did), "{file}");

    // The other device is untouched.
    let resp = n.call_as(&tv, "tenzro_listPairedDevices", json!({})).await;
    let devices = resp["result"]["devices"].as_array().expect("devices");
    assert_eq!(devices.len(), 1, "{resp}");
    assert_eq!(devices[0]["id"], tv_did, "{resp}");
    assert_eq!(devices[0]["label"], "Kitchen TV", "{resp}");

    // An administrator removes any device; one that is not paired is an error.
    let resp = n
        .call_as(&op, "tenzro_unpairDevice", json!({ "id": phone_did }))
        .await;
    assert_eq!(resp["error"]["code"], -32602, "{resp}");
    let resp = n
        .call_as(&op, "tenzro_unpairDevice", json!({ "id": tv_did }))
        .await;
    assert_eq!(resp["result"]["unpaired"], tv_did, "{resp}");
    let resp = n.call_as(&tv, "tenzro_listPairedDevices", json!({})).await;
    assert_eq!(resp["error"]["code"], -32004, "{resp}");
    let resp = n.call_as(&op, "tenzro_listPairedDevices", json!({})).await;
    assert_eq!(resp["result"]["devices"], json!([]), "{resp}");
    assert!(
        !n.policy_file().contains("rpc:tenzro_"),
        "{}",
        n.policy_file()
    );
    n.stop().await;
}

#[tokio::test]
async fn a_paired_device_acts_on_the_node_only_with_the_operators_passkey() {
    let operator = OperatorKey::new();
    let n = TestNode::start(&operator).await;
    let op = operator.sign_in(&n.client, &n.url).await;
    let (phone_did, phone) = n.pair(&op, "Hall phone", "phone").await;

    // It reads the node's conditions as they are.
    let resp = n.call_as(&phone, "tenzro_listConditions", json!({})).await;
    assert!(resp["error"].is_null(), "{resp}");

    // Restarting and installing are refused without the operator's passkey on
    // the call, with a challenge to sign; one that does not verify spends it.
    for method in ["tenzro_restartNode", "tenzro_installUpdate"] {
        let resp = n.call_as(&phone, method, json!({})).await;
        assert_eq!(resp["error"]["code"], -32004, "{method}: {resp}");
        let challenge = resp["error"]["data"]["challenge"]
            .as_str()
            .expect("challenge");
        assert_eq!(challenge.len(), 43, "{method}: {resp}");
        let forged = json!({ "assertion": {
            "credential_id": "AA",
            "authenticator_data": "AA",
            "client_data_json": "AA",
            "signature": "AA",
        }});
        let resp = n.call_as(&phone, method, forged.clone()).await;
        assert!(resp["result"].is_null(), "{method}: {resp}");
        assert!(resp["error"]["data"].is_null(), "{method}: {resp}");
        let resp = n.call_as(&phone, method, forged).await;
        let message = resp["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.starts_with("no challenge is waiting"),
            "{method}: {resp}"
        );
    }

    // Approving reaches the approval, which asks for the passkey itself.
    let resp = n
        .call_as(
            &phone,
            "tenzro_submitApproval",
            json!({ "condition_id": "none", "approve": true }),
        )
        .await;
    assert_ne!(resp["error"]["code"], -32004, "{resp}");
    assert!(resp["result"].is_null(), "{resp}");

    // An administrator's restart goes straight to whether anything would
    // start the node again.
    let resp = n.call_as(&op, "tenzro_restartNode", json!({})).await;
    assert!(resp["error"]["data"].is_null(), "{resp}");

    // Unpairing withdraws all four.
    let resp = n
        .call_as(&op, "tenzro_unpairDevice", json!({ "id": phone_did }))
        .await;
    assert_eq!(resp["result"]["unpaired"], phone_did, "{resp}");
    for (method, params) in [
        ("tenzro_listConditions", json!({})),
        ("tenzro_restartNode", json!({})),
        ("tenzro_installUpdate", json!({})),
        (
            "tenzro_submitApproval",
            json!({ "condition_id": "none", "approve": false }),
        ),
    ] {
        let resp = n.call_as(&phone, method, params).await;
        assert_eq!(resp["error"]["code"], -32004, "{method}: {resp}");
        assert!(resp["error"]["data"].is_null(), "{method}: {resp}");
    }
    n.stop().await;
}

#[tokio::test]
async fn a_television_waits_for_the_operators_passkey_to_sign_in() {
    let operator = OperatorKey::new();
    let n = TestNode::start(&operator).await;
    let op = operator.sign_in(&n.client, &n.url).await;
    let ask = |label: &'static str| {
        n.call(
            "tenzro_requestDeviceCode",
            json!({ "dpop_jkt": "the television's key thumbprint", "label": label }),
        )
    };
    let lounge = ask("Lounge TV").await;
    assert_eq!(lounge["result"]["interval"], 5, "{lounge}");
    assert_eq!(lounge["result"]["expires_in"], 600, "{lounge}");
    let lounge_code = lounge["result"]["device_code"]
        .as_str()
        .expect("device code");
    let lounge_user = lounge["result"]["user_code"].as_str().expect("user code");
    assert_eq!(lounge_user.len(), 9, "{lounge}");
    let kitchen = ask("Kitchen TV").await;
    let kitchen_code = kitchen["result"]["device_code"]
        .as_str()
        .expect("device code");
    let kitchen_user = kitchen["result"]["user_code"].as_str().expect("user code");

    // Two codes wait per address.
    let resp = ask("Hall TV").await;
    assert_eq!(resp["error"]["code"], -32004, "{resp}");

    // The device waits, and is told to slow down when it polls too soon.
    let poll = |code: &str| n.call("tenzro_pollDeviceCode", json!({ "device_code": code }));
    let resp = poll(lounge_code).await;
    assert_eq!(
        resp["error"]["data"]["error"], "authorization_pending",
        "{resp}"
    );
    let resp = poll(lounge_code).await;
    assert_eq!(resp["error"]["data"]["error"], "slow_down", "{resp}");
    let resp = poll("bm8gc3VjaCBjb2Rl").await;
    assert_eq!(resp["error"]["data"]["error"], "expired_token", "{resp}");

    // Nobody but an administrator or a paired device answers it.
    let approve = json!({ "user_code": lounge_user, "approve": true });
    let stranger = OperatorKey::new().sign_in(&n.client, &n.url).await;
    let resp = n
        .call_as(&stranger, "tenzro_approveDeviceCode", approve.clone())
        .await;
    assert_eq!(resp["error"]["code"], -32004, "{resp}");
    let resp = n.call("tenzro_approveDeviceCode", approve.clone()).await;
    assert_eq!(resp["error"]["code"], -32004, "{resp}");

    // Approving asks for the operator's passkey on the call itself, and an
    // assertion that does not verify approves nothing.
    let resp = n
        .call_as(&op, "tenzro_approveDeviceCode", approve.clone())
        .await;
    assert_eq!(resp["error"]["code"], -32004, "{resp}");
    let challenge = resp["error"]["data"]["challenge"]
        .as_str()
        .expect("challenge");
    assert_eq!(challenge.len(), 43, "{resp}");
    assert_eq!(resp["error"]["data"]["label"], "Lounge TV", "{resp}");
    let mut forged = approve.clone();
    forged["assertion"] = json!({
        "credential_id": "AA",
        "authenticator_data": "AA",
        "client_data_json": "AA",
        "signature": "AA",
    });
    let resp = n.call_as(&op, "tenzro_approveDeviceCode", forged).await;
    assert!(resp["result"].is_null(), "{resp}");
    let resp = n.call_as(&op, "tenzro_listPairedDevices", json!({})).await;
    assert_eq!(resp["result"]["devices"], json!([]), "{resp}");

    // Declining ends the wait.
    let resp = n
        .call_as(
            &op,
            "tenzro_approveDeviceCode",
            json!({ "user_code": kitchen_user.to_lowercase(), "approve": false }),
        )
        .await;
    assert_eq!(resp["result"]["approved"], false, "{resp}");
    let resp = poll(kitchen_code).await;
    assert_eq!(resp["error"]["data"]["error"], "access_denied", "{resp}");
    let resp = n
        .call_as(
            &op,
            "tenzro_approveDeviceCode",
            json!({ "user_code": kitchen_user, "approve": true }),
        )
        .await;
    assert_eq!(resp["error"]["code"], -32602, "{resp}");
    n.stop().await;
}

#[tokio::test]
async fn a_device_signs_in_with_the_code_for_a_token_that_only_redeems_it() {
    let operator = OperatorKey::new();
    let n = TestNode::start(&operator).await;
    let op = operator.sign_in(&n.client, &n.url).await;
    let (id, code) = n.start_pairing(&op).await;
    let phone_key = OperatorKey::new();

    // A code with a wrong secret, or one naming no waiting pairing, signs
    // nobody in; an administrator is not paired as a device.
    for wrong in [wrong_secret(&code), miscopied(&code, 0)] {
        let resp = n.refused_sign_in(&phone_key, &wrong).await;
        assert_eq!(resp["error"]["code"], -32602, "{resp}");
    }
    let resp = n.refused_sign_in(&operator, &code).await;
    assert_eq!(resp["error"]["code"], -32602, "{resp}");
    assert_eq!(n.pairing(&op, &id).await["state"], "waiting");

    // The code signs the device in without spending it, for a short token
    // that carries no method class.
    let (phone, issued) = phone_key
        .sign_in_with(&n.client, &n.url, Some(&code))
        .await
        .expect("sign-in with the code");
    assert_eq!(issued["classes"], json!([]), "{issued}");
    let expires_in = issued["expires_in"].as_u64().expect("expires_in");
    assert!((1..=300).contains(&expires_in), "{issued}");
    assert_eq!(n.pairing(&op, &id).await["state"], "waiting");

    // That token is refused on a read, on the paired calls and on an
    // administrator's call, and starts or reads no pairing.
    for (method, params) in [
        ("eth_blockNumber", json!([])),
        ("tenzro_listPairedDevices", json!({})),
        ("tenzro_unpairDevice", json!({ "id": phone_key.did() })),
        ("tenzro_getAccessPolicy", json!({})),
    ] {
        let resp = n.call_as(&phone, method, params).await;
        assert_eq!(resp["error"]["code"], -32001, "{method}: {resp}");
    }
    for params in [json!({}), json!({ "id": id })] {
        let resp = n.call_as(&phone, "tenzro_pairDevice", params).await;
        assert_eq!(resp["error"]["code"], -32004, "{resp}");
    }

    // It redeems the code, and stays the token it was.
    let redeem = json!({ "secret": code, "label": "Hall phone", "kind": "phone" });
    let resp = n.call_as(&phone, "tenzro_pairDevice", redeem).await;
    assert_eq!(resp["result"]["device"]["id"], phone_key.did(), "{resp}");
    assert_eq!(n.pairing(&op, &id).await["state"], "done");
    let resp = n
        .call_as(&phone, "tenzro_listPairedDevices", json!({}))
        .await;
    assert_eq!(resp["error"]["code"], -32001, "{resp}");

    // Signed in again as the paired device it now is, it makes the paired
    // calls; the spent code signs nobody else in.
    let phone = phone_key.sign_in(&n.client, &n.url).await;
    let resp = n
        .call_as(&phone, "tenzro_listPairedDevices", json!({}))
        .await;
    let devices = resp["result"]["devices"].as_array().expect("devices");
    assert_eq!(devices.len(), 1, "{resp}");
    assert_eq!(devices[0]["this_device"], true, "{resp}");
    let resp = n.refused_sign_in(&OperatorKey::new(), &code).await;
    assert_eq!(resp["error"]["code"], -32602, "{resp}");
    n.stop().await;
}

#[tokio::test]
async fn wrong_codes_cancel_the_pairing_they_name_and_quiet_their_source() {
    let operator = OperatorKey::new();
    let n = TestNode::start(&operator).await;
    let op = operator.sign_in(&n.client, &n.url).await;
    let (first, first_code) = n.start_pairing(&op).await;
    let (second, second_code) = n.start_pairing(&op).await;
    let device = OperatorKey::new().sign_in(&n.client, &n.url).await;

    // Five wrong secrets for the first pairing cancel it, and say why.
    let wrong =
        json!({ "secret": wrong_secret(&first_code), "label": "Hall phone", "kind": "phone" });
    for _ in 0..5 {
        assert_eq!(n.pairing(&op, &first).await["state"], "waiting");
        let resp = n.call_as(&device, "tenzro_pairDevice", wrong.clone()).await;
        assert_eq!(resp["error"]["code"], -32602, "{resp}");
    }
    let cancelled = n.pairing(&op, &first).await;
    assert_eq!(cancelled["state"], "failed", "{cancelled}");
    assert_eq!(
        cancelled["reason"], "5 wrong codes were presented for this pairing; start a new one",
        "{cancelled}"
    );

    // The second pairing still waits. Every call here comes from one address,
    // which sent five wrong codes: its next code is refused unread, at
    // sign-in and at redeem, and the pairing it names is not spent.
    assert_eq!(n.pairing(&op, &second).await["state"], "waiting");
    let redeem = json!({ "secret": second_code, "label": "Hall phone", "kind": "phone" });
    let resp = n.call_as(&device, "tenzro_pairDevice", redeem).await;
    assert_eq!(resp["error"]["code"], -32004, "{resp}");
    let resp = n.refused_sign_in(&OperatorKey::new(), &second_code).await;
    assert_eq!(resp["error"]["code"], -32004, "{resp}");
    assert_eq!(n.pairing(&op, &second).await["state"], "waiting");
    n.stop().await;
}

/// A TLS client that accepts exactly the certificates whose SHA-256 is in
/// `pins`, as a paired device does with the hashes its QR code carried.
#[cfg(feature = "paired-devices")]
#[derive(Debug)]
struct Pinned {
    pins: Vec<String>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

#[cfg(feature = "paired-devices")]
impl rustls::client::danger::ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        use sha2::Digest as _;
        let hash = hex::encode(sha2::Sha256::digest(end_entity.as_ref()));
        if self.pins.contains(&hash) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "not a pinned certificate".to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(feature = "paired-devices")]
fn pinned_client(pins: Vec<String>) -> reqwest::Client {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned { pins, provider }))
        .with_no_client_auth();
    reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .http1_only()
        .build()
        .expect("client")
}

#[cfg(feature = "paired-devices")]
async fn post(client: &reqwest::Client, url: &str, body: Value) -> Value {
    client
        .post(url)
        .json(&body)
        .send()
        .await
        .expect("HTTP")
        .json()
        .await
        .expect("JSON")
}

#[cfg(feature = "paired-devices")]
#[tokio::test]
async fn a_device_pairs_and_reads_over_the_listener_whose_certificate_it_pins() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::ecdsa::signature::hazmat::PrehashVerifier as _;

    let operator = OperatorKey::new();
    let n = TestNode::start_with_listener(&operator).await;
    let op = operator.sign_in(&n.client, &n.url).await;

    // Starting a pairing opens the listener; the answer and the QR code say
    // where it is and which certificates it serves under.
    let resp = n.call_as(&op, "tenzro_pairDevice", json!({})).await;
    let started = &resp["result"];
    assert_eq!(started["state"], "waiting", "{resp}");
    assert_eq!(started["lan"]["unavailable"], "", "{resp}");
    let addresses = started["lan"]["addresses"].as_array().expect("addresses");
    assert_eq!(addresses.len(), 1, "{resp}");
    let address = addresses[0].as_str().expect("address").to_string();
    assert!(address.starts_with("127.0.0.1:"), "{address}");
    let pins: Vec<String> = started["lan"]["pins"]
        .as_array()
        .expect("pins")
        .iter()
        .map(|pin| pin.as_str().expect("pin").to_string())
        .collect();
    assert!(!pins.is_empty(), "{resp}");
    let url = started["url"].as_str().expect("url");
    assert!(
        url.contains(&format!("lan={}&", urlencoding::encode(&address))),
        "{url}"
    );
    for pin in &pins {
        assert_eq!(pin.len(), 64, "{pin}");
        assert!(url.contains(&format!("pin={pin}&")), "{url}");
    }
    let code = started["code"].as_str().expect("code").to_string();

    // A client pinning another certificate does not get through.
    let lan = format!("https://{address}");
    let stranger = pinned_client(vec!["00".repeat(32)]);
    let syncing = json!({ "jsonrpc": "2.0", "id": 1, "method": "tenzro_syncing", "params": [] });
    assert!(stranger.post(&lan).json(&syncing).send().await.is_err());

    // The device signs in with the code and redeems it, all over the listener.
    let device_client = pinned_client(pins.clone());
    let key = OperatorKey::new();
    let (redeemer, _) = key
        .sign_in_with(&device_client, &lan, Some(&code))
        .await
        .expect("sign-in with the code");
    let resp = redeemer
        .call(
            &device_client,
            &lan,
            "tenzro_pairDevice",
            json!({ "secret": code, "label": "Hall phone", "kind": "phone" }),
        )
        .await;
    assert_eq!(resp["result"]["device"]["id"], key.did(), "{resp}");
    let node_key = resp["result"]["node_key"].clone();
    assert_eq!(node_key["kty"], "EC", "{resp}");

    // Paired, it signs in again there and makes its calls.
    let device = key.sign_in(&device_client, &lan).await;
    let resp = device
        .call(&device_client, &lan, "tenzro_listPairedDevices", json!({}))
        .await;
    let devices = resp["result"]["devices"].as_array().expect("devices");
    assert_eq!(devices.len(), 1, "{resp}");
    assert_eq!(devices[0]["this_device"], true, "{resp}");
    let resp = post(&device_client, &lan, syncing.clone()).await;
    assert!(resp["error"].is_null(), "{resp}");

    // A method the listener does not serve is not found there, alone or in a
    // batch, for the operator too; the node's own listener still serves it.
    let height = json!({ "jsonrpc": "2.0", "id": 7, "method": "eth_blockNumber", "params": [] });
    let resp = post(&device_client, &lan, height.clone()).await;
    assert_eq!(resp["error"]["code"], -32601, "{resp}");
    assert_eq!(
        resp["error"]["message"], "Method not found: eth_blockNumber",
        "{resp}"
    );
    assert_eq!(resp["id"], 7, "{resp}");
    let resp = post(&device_client, &lan, json!([syncing, height])).await;
    let answers = resp.as_array().expect("batch");
    assert!(answers[0]["error"].is_null(), "{resp}");
    assert_eq!(answers[1]["error"]["code"], -32601, "{resp}");
    let op_there = operator.sign_in(&device_client, &lan).await;
    let resp = op_there
        .call(&device_client, &lan, "tenzro_getAccessPolicy", json!({}))
        .await;
    assert_eq!(resp["error"]["code"], -32601, "{resp}");
    let resp = post(&n.client, &n.url, height).await;
    assert!(resp["error"].is_null(), "{resp}");

    // The listener publishes its certificates under the node's signing key.
    let publication: tenzro_node::pinned_cert::Publication = device_client
        .get(format!("{lan}/certificates"))
        .send()
        .await
        .expect("HTTP")
        .json()
        .await
        .expect("publication");
    assert_eq!(publication.listener, "paired-devices");
    assert_eq!(publication.kid, node_key["kid"].as_str().expect("kid"));
    let published: Vec<String> = publication
        .hashes
        .iter()
        .map(|h| h.sha256.clone())
        .collect();
    assert_eq!(published, pins);
    let digest = tenzro_node::pinned_cert::publication_digest(
        &publication.issuer,
        &publication.listener,
        &publication.hashes,
        publication.signed_at,
    )
    .expect("digest");
    let coordinate = |name: &str| {
        URL_SAFE_NO_PAD
            .decode(node_key[name].as_str().expect("coordinate"))
            .expect("base64url")
    };
    let point = [vec![4u8], coordinate("x"), coordinate("y")].concat();
    let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).expect("node key");
    let signature = p256::ecdsa::Signature::from_slice(
        &URL_SAFE_NO_PAD
            .decode(&publication.signature)
            .expect("base64url"),
    )
    .expect("signature");
    verifying
        .verify_prehash(&digest, &signature)
        .expect("the node signed its certificates");

    n.stop().await;
}
