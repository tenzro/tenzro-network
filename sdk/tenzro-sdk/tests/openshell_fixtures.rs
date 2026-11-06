//! The OpenShell vectors (`sdk/fixtures/openshell`), shared with the TS and
//! Python SDKs: grants to Terms, session ids, sessions the tenzro-openshell
//! extensions signed, verified offline with every tampering refused, and a
//! credential minted under the grant with the passkey.

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use tenzro_sdk::TenzroClient;
use tenzro_sdk::config::SdkConfig;
use tenzro_sdk::openshell::{
    OpenShellIdentity, OpenShellSignedEntry, OpenShellTermsOptions, OpenShellVerifyOptions,
    mint_openshell_credential, openshell_payments, openshell_session_id, openshell_terms,
    parse_openshell_entries, verify_openshell_receipt, verify_openshell_session,
};
use tenzro_sdk::rpc::RpcClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const VECTORS: &str = include_str!("../../fixtures/openshell/vectors.json");
const POLICY: &str = include_str!("../../fixtures/openshell/policy_terms.json");

fn v() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn p() -> Value {
    serde_json::from_str(POLICY).unwrap()
}

fn options() -> OpenShellTermsOptions {
    serde_json::from_value(p()["options"].clone()).unwrap()
}

fn opts(c: &Value) -> OpenShellVerifyOptions {
    OpenShellVerifyOptions {
        identity: serde_json::from_value::<OpenShellIdentity>(c["identity"].clone()).unwrap(),
        hybrid_records_from_ms: c["hybrid_records_from_ms"].as_u64(),
        session_id: None,
    }
}

fn entries(c: &Value) -> Vec<OpenShellSignedEntry> {
    serde_json::from_value(c["entries"].clone()).unwrap()
}

#[test]
fn every_grant_maps_to_the_terms_the_vectors_state() {
    let p = p();
    let cases = p["cases"].as_array().unwrap();
    assert!(cases.len() >= 4);
    for c in cases {
        let terms = openshell_terms(&c["policy"], &c["grant"], &options()).unwrap();
        assert_eq!(terms, c["terms"], "{}", c["name"]);
    }
}

#[test]
fn every_grant_or_policy_the_mapping_must_refuse_is_refused_with_its_reason() {
    let p = p();
    let refusals = p["refusals"].as_array().unwrap();
    assert!(refusals.len() >= 15);
    for c in refusals {
        let err = openshell_terms(&c["policy"], &c["grant"], &options()).unwrap_err();
        let want = c["error"].as_str().unwrap();
        assert!(err.to_string().contains(want), "{}: {err}", c["name"]);
    }
}

#[test]
fn session_ids_are_the_extensions_layout() {
    for c in v()["session_ids"].as_array().unwrap() {
        assert_eq!(
            openshell_session_id(
                c["gateway"].as_str().unwrap(),
                c["session"].as_str().unwrap()
            ),
            c["session_id"].as_str().unwrap()
        );
    }
}

#[test]
fn sessions_the_extensions_signed_verify_with_their_root_kinds_and_payments() {
    let v = v();
    let sessions = v["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 3);
    for s in sessions {
        let x = &s["expect"];
        let mut o = opts(s);
        o.session_id = Some(x["session_id"].as_str().unwrap().to_string());
        let got = verify_openshell_session(&entries(s), &o).unwrap();
        assert_eq!(
            got.session_id,
            x["session_id"].as_str().unwrap(),
            "{}",
            s["name"]
        );
        assert_eq!(got.agent, x["agent"].as_str().unwrap());
        assert_eq!(got.count, x["count"].as_u64().unwrap());
        assert_eq!(got.root, x["root"].as_str().unwrap());
        let kinds: Vec<&str> = got.entries.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(json!(kinds), x["kinds"]);
        assert!(
            got.entries
                .iter()
                .all(|e| e.image.as_deref() == x["image"].as_str())
        );
        assert_eq!(
            serde_json::to_value(openshell_payments(&got).unwrap()).unwrap(),
            x["payments"]
        );
        for e in got.entries.iter().filter(|e| e.kind == "tool_call") {
            assert_eq!(e.call.as_ref().unwrap()["surface"], "openshell");
        }
    }
    let hybrid = verify_openshell_session(&entries(&sessions[1]), &opts(&sessions[1])).unwrap();
    assert!(hybrid.entries.iter().all(|e| e.hybrid));
}

#[test]
fn entries_parse_from_json_lines_and_from_an_array() {
    let v = v();
    let s = &v["sessions"][0];
    let lines: Vec<String> = s["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(Value::to_string)
        .collect();
    assert_eq!(
        parse_openshell_entries(&lines.join("\n")).unwrap(),
        entries(s)
    );
    assert_eq!(
        parse_openshell_entries(&s["entries"].to_string()).unwrap(),
        entries(s)
    );
}

#[test]
fn a_model_calls_receipt_header_verifies() {
    let v = v();
    let r = &v["receipt"];
    let o = opts(r);
    let e = verify_openshell_receipt(
        r["header"].as_str().unwrap(),
        &o.identity,
        o.hybrid_records_from_ms,
    )
    .unwrap();
    assert_eq!(e.kind, r["expect"]["kind"].as_str().unwrap());
    assert_eq!(e.action, r["expect"]["action"].as_str().unwrap());
    assert_eq!(e.linked_tx.as_deref(), r["expect"]["linked_tx"].as_str());
}

#[test]
fn every_tampering_is_refused_with_its_reason() {
    let v = v();
    let refusals = v["refusals"].as_array().unwrap();
    assert!(refusals.len() >= 6);
    for c in refusals {
        let err = verify_openshell_session(&entries(c), &opts(c)).unwrap_err();
        assert!(
            err.to_string().contains(c["error"].as_str().unwrap()),
            "{}: {err}",
            c["name"]
        );
    }
}

/// A node stand-in that answers the custody challenge with the terms it was
/// sent, and the onboarding with a minted agent; it records every request.
async fn node(sent: Arc<Mutex<Vec<Value>>>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let sent = sent.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                let start = loop {
                    let n = sock.read(&mut chunk).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..start]).to_lowercase();
                let len: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .map(|v| v.trim().parse().unwrap())
                    .unwrap_or(0);
                while buf.len() < start + len {
                    let n = sock.read(&mut chunk).await.unwrap();
                    buf.extend_from_slice(&chunk[..n]);
                }
                let request: Value = serde_json::from_slice(&buf[start..]).unwrap();
                let params = match &request["params"] {
                    Value::Array(a) if a.len() == 1 => a[0].clone(),
                    p => p.clone(),
                };
                let result = match request["method"].as_str().unwrap() {
                    "tenzro_createCustodyChallenge" => json!({
                        "challenge_id": "ch-1",
                        "challenge_hex": format!("0x{}", "aa".repeat(32)),
                        "webauthn_challenge": "Y2g",
                        "account_address": params["account_address"],
                        "target_hex": format!("0x{}", "bb".repeat(32)),
                        "nonce_hex": format!("0x{}", "cc".repeat(16)),
                        "expires_in_secs": 300,
                        "delegation": params["delegation"],
                    }),
                    "tenzro_onboardDelegatedAgent" => json!({
                        "identity": { "did": "did:tenzro:agent:minted" },
                        "wallet": { "address": format!("0x{}", "22".repeat(20)) },
                        "serving_nodes": params["delegation"]["serving_nodes"],
                        "min_distinct_operators": 1,
                    }),
                    m => panic!("unexpected {m}"),
                };
                sent.lock()
                    .unwrap()
                    .push(json!({ "method": request["method"], "params": params }));
                let body =
                    json!({ "jsonrpc": "2.0", "id": request["id"], "result": result }).to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                sock.write_all(response.as_bytes()).await.unwrap();
            });
        }
    });
    url
}

#[tokio::test]
async fn minting_a_credential_delegates_the_agent_under_the_grant_with_the_passkey() {
    let p = p();
    let c = &p["cases"][0];
    let sent = Arc::new(Mutex::new(Vec::new()));
    let url = node(sent.clone()).await;
    let rpc = RpcClient::new(&url, std::time::Duration::from_secs(10), None).unwrap();
    let client =
        TenzroClient::with_rpc(SdkConfig::builder().endpoint(&url).build().unwrap(), rpc).unwrap();
    let approvals = Arc::new(Mutex::new(Vec::new()));
    let seen = approvals.clone();
    let cred = mint_openshell_credential(
        &client.auth(),
        &format!("0x{}", "11".repeat(20)),
        &c["policy"],
        &c["grant"],
        &options(),
        |challenge| async move {
            seen.lock().unwrap().push(challenge.challenge_id.clone());
            Ok(json!({ "challenge_id": challenge.challenge_id, "assertion": "passkey" }))
        },
    )
    .await
    .unwrap();
    let sent = sent.lock().unwrap().clone();
    let methods: Vec<&str> = sent.iter().map(|r| r["method"].as_str().unwrap()).collect();
    assert_eq!(
        methods,
        [
            "tenzro_createCustodyChallenge",
            "tenzro_onboardDelegatedAgent"
        ]
    );
    assert_eq!(sent[0]["params"]["operation"], "delegate_agent");
    assert_eq!(sent[0]["params"]["delegation"], c["terms"]);
    assert_eq!(*approvals.lock().unwrap(), vec!["ch-1".to_string()]);
    assert_eq!(cred.agent_did, "did:tenzro:agent:minted");
    assert_eq!(
        cred.provider,
        json!({
            "name": "tenzro",
            "type": "tenzro",
            "credentials": { "TENZRO_AGENT_TOKEN": "did:tenzro:agent:minted" }
        })
    );
    assert_eq!(
        cred.annotation,
        json!({ "tenzro.agent": "did:tenzro:agent:minted" })
    );
}
