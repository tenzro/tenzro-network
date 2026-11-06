//! Identity, access, agents, payments, settlement, governance and bridge
//! bindings against a JSON-RPC node stand-in: each binding names the node's
//! method and sends the params its handler reads, as the node sees them (a
//! one-object array unwrapped).

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tenzro_sdk::config::SdkConfig;
use tenzro_sdk::device::{BindDeviceRequest, DeviceAssertion, TransferAuthority};
use tenzro_sdk::error::SdkResult;
use tenzro_sdk::passkey_client::{
    CreatePasskeySessionParams, CustodyAuthorization, CustodyOperation, EnrollPasskeyParams,
    RevokeJwtParams,
};
use tenzro_sdk::rpc::RpcClient;
use tenzro_sdk::wallet::HybridSigner;
use tenzro_sdk::{
    Address, AuditFilter, PageRequest, RegisterHumanParams, SettlementRequest, TenzroClient,
    TxKind, TypedTransaction,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DID: &str = "did:tenzro:human:aa";
const AGENT: &str = "did:tenzro:machine:aa:bb";
const ADDR: &str = "0x0303030303030303030303030303030303030303030303030303030303030303";

fn h32() -> String {
    "ab".repeat(32)
}

/// The node's `plain` signing payload for a typed transaction request.
fn plain_payload(r: &Value) -> Value {
    let encoded = r["tx_type"].to_string();
    let hex32 = |k: &str| hex::decode(r[k].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let mut h = Sha256::new();
    h.update(r["chain_id"].as_u64().unwrap().to_le_bytes());
    h.update(hex32("from"));
    h.update(hex32("to"));
    h.update(r["nonce"].as_u64().unwrap().to_le_bytes());
    h.update(r["gas_limit"].as_u64().unwrap().to_le_bytes());
    h.update(r["gas_price"].as_u64().unwrap().to_le_bytes());
    h.update(r["timestamp"].as_i64().unwrap().to_le_bytes());
    h.update(r["valid_until"].as_i64().unwrap().to_le_bytes());
    h.update(encoded.as_bytes());
    json!({ "kind": "plain", "digest": hex::encode(h.finalize()), "tx_type_json": encoded })
}

fn decode_preimage() -> Vec<u8> {
    serde_json::to_vec(&json!({ "action": { "Transfer": { "amount": 1 } } })).unwrap()
}

fn answer(method: &str, params: &Value) -> Value {
    match method {
        "tenzro_getBalance" | "tenzro_getNonce" => json!("0x5"),
        "eth_chainId" => json!("0x20aa9"),
        "eth_gasPrice" => json!("0x1"),
        "tenzro_getSigningPayload" => plain_payload(params),
        "tenzro_createCustodyChallenge" => json!({
            "challenge_id": "c1",
            "challenge_hex": format!("0x{}", "33".repeat(32)),
            "webauthn_challenge": "w",
            "account_address": format!("0x{}", "11".repeat(32)),
            "target_hex": "0x",
            "nonce_hex": format!("0x{}", "22".repeat(16)),
            "expires_in_secs": 60,
            "delegation": { "completed": true },
        }),
        "tenzro_decodeAction" => {
            let p = decode_preimage();
            json!({ "preimage_hex": hex::encode(&p), "digest": hex::encode(Sha256::digest(&p)) })
        }
        _ => json!({ "answered": method }),
    }
}

/// Unwraps a one-object array, as the node's dispatcher does.
fn seen(params: &Value) -> Value {
    match params.as_array() {
        Some(a) if a.len() == 1 && a[0].is_object() => a[0].clone(),
        _ => params.clone(),
    }
}

#[derive(Clone, Default)]
struct Node {
    sent: Arc<Mutex<Vec<Value>>>,
}

impl Node {
    async fn start(&self) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let sent = self.sent.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                let sent = sent.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 8192];
                    let body_start = loop {
                        let n = sock.read(&mut chunk).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..body_start]).to_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .map(|v| v.trim().parse().unwrap())
                        .unwrap_or(0);
                    while buf.len() < body_start + len {
                        let n = sock.read(&mut chunk).await.unwrap();
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    let request: Value = serde_json::from_slice(&buf[body_start..]).unwrap();
                    let method = request["method"].as_str().unwrap_or_default().to_string();
                    let result = answer(&method, &seen(&request["params"]));
                    sent.lock().unwrap().push(request.clone());
                    let body = json!({ "jsonrpc": "2.0", "id": request["id"], "result": result })
                        .to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(response.as_bytes()).await;
                });
            }
        });
        url
    }

    /// The params the node read on the last call of `method`.
    fn last(&self, method: &str) -> Value {
        let sent = self.sent.lock().unwrap();
        let r = sent
            .iter()
            .rev()
            .find(|r| r["method"] == method)
            .unwrap_or_else(|| panic!("{method} was not called"));
        seen(&r["params"])
    }
}

struct Signer;

#[async_trait::async_trait]
impl HybridSigner for Signer {
    fn p256_public_key(&self) -> [u8; 64] {
        [7; 64]
    }
    fn ml_dsa_public_key(&self) -> Option<Vec<u8>> {
        None
    }
    async fn sign_composite(&self, _m: &[u8]) -> SdkResult<([u8; 64], Option<Vec<u8>>)> {
        Ok(([9; 64], None))
    }
    async fn sign_p256(&self, _m: &[u8]) -> SdkResult<[u8; 64]> {
        Ok([9; 64])
    }
}

struct Prover;

impl tenzro_sdk::DpopProver for Prover {
    fn jkt(&self) -> SdkResult<String> {
        Ok("jkt".into())
    }
    fn proof(&self, _htm: &str, _htu: &str, _token: &str) -> SdkResult<String> {
        Ok("proof".into())
    }
}

struct PqKey;

#[async_trait::async_trait]
impl tenzro_sdk::PqRotationKey for PqKey {
    fn verifying_key(&self) -> Vec<u8> {
        vec![1; 4]
    }
    fn backend(&self) -> &'static str {
        "tpm"
    }
    async fn sign_ml_dsa(&self, _c: &[u8], _m: &[u8]) -> SdkResult<Vec<u8>> {
        Ok(vec![2; 4])
    }
}

fn assertion() -> DeviceAssertion {
    DeviceAssertion {
        credential_id: "Y3JlZA".into(),
        authenticator_data_b64: "YQ".into(),
        client_data_json_b64: "Yw".into(),
        signature_b64: "cw".into(),
    }
}

fn custody_authorization() -> CustodyAuthorization {
    CustodyAuthorization {
        challenge_id: "c1".into(),
        credential_id_hex: "cd".into(),
        assertion: json!({ "a": 1 }),
        ml_dsa_signature_hex: None,
        anchor: None,
    }
}

#[tokio::test]
async fn every_binding_sends_the_params_the_node_reads() {
    let node = Node::default();
    let url = node.start().await;
    let rpc = RpcClient::new(&url, std::time::Duration::from_secs(10), None).unwrap();
    let c =
        TenzroClient::with_rpc(SdkConfig::builder().endpoint(&url).build().unwrap(), rpc).unwrap();
    let s = Signer;
    let signer: Arc<dyn HybridSigner> = Arc::new(Signer);
    let h = h32();
    let mut covered: BTreeSet<String> = BTreeSet::new();
    macro_rules! expect {
        ($method:expr, $want:expr $(,)?) => {{
            let method: &str = $method;
            assert_eq!(node.last(method), $want, "{method}");
            covered.insert(method.to_string());
        }};
    }

    // Access
    let _ = c.access().challenge(DID, "jkt").await;
    expect!(
        "tenzro_accessChallenge",
        json!({ "did": DID, "dpop_jkt": "jkt" })
    );
    let proof = tenzro_sdk::SignInProof::Device {
        public_key: "aa".into(),
        signature: "bb".into(),
    };
    let _ = c.access().issue("c1", &proof, None).await;
    expect!(
        "tenzro_issueAccessToken",
        json!({ "challenge_id": "c1", "proof": serde_json::to_value(&proof).unwrap() }),
    );
    let _ = c.access().get_policy().await;
    expect!("tenzro_getAccessPolicy", json!({}));
    let _ = c.access().set_policy("x = 1").await;
    expect!("tenzro_setAccessPolicy", json!({ "toml": "x = 1" }));
    let _ = c
        .access()
        .preview("rpc", "tenzro_getBalance", Some(DID))
        .await;
    expect!(
        "tenzro_previewAccess",
        json!({ "surface": "rpc", "method": "tenzro_getBalance", "did": DID }),
    );
    let _ = c.access().list_tokens().await;
    expect!("tenzro_listAccessTokens", json!({}));
    let _ = c.access().revoke_did(DID).await;
    expect!("tenzro_revokeAccessToken", json!({ "did": DID }));
    let filter = AuditFilter {
        method: Some("tenzro_stopModel".into()),
        limit: Some(5),
        ..AuditFilter::default()
    };
    let _ = c.access().audit_log(&filter).await;
    expect!(
        "tenzro_listAdminAudit",
        json!({ "method": "tenzro_stopModel", "limit": 5 }),
    );
    let _ = c.access().verify_audit_log().await;
    expect!("tenzro_verifyAdminAudit", json!({}));

    // Auth, onboarding and agents
    let key = "07".repeat(64);
    let _ = c
        .auth()
        .onboard_human("Alice", "cd", &key, None, |_| async {
            Ok(custody_authorization())
        })
        .await;
    expect!(
        "tenzro_onboardHuman",
        json!({
            "display_name": "Alice",
            "credential_id": "cd",
            "public_key": key,
            "authorization": serde_json::to_value(custody_authorization()).unwrap(),
        }),
    );
    let _ = c
        .auth()
        .delegate_agent("0x11", json!({ "agent_name": "a" }), |_| async {
            Ok(json!({ "ok": 1 }))
        })
        .await;
    expect!(
        "tenzro_onboardDelegatedAgent",
        json!({ "delegation": { "completed": true }, "authorization": { "ok": 1 } }),
    );
    let _ = c.auth().onboard_autonomous_agent("04aa", "m1", None).await;
    expect!(
        "tenzro_onboardAutonomousAgent",
        json!({ "device_public_key": "04aa", "machine_id": "m1" }),
    );
    let act = tenzro_sdk::auth::AgentActRequest {
        operation: "pay".into(),
        counterparty: Some(ADDR.into()),
        ..Default::default()
    };
    let _ = c.auth().agent_act(act).await;
    expect!(
        "tenzro_agentAct",
        json!({ "operation": "pay", "counterparty": ADDR }),
    );
    let _ = c.auth().agent_voucher(&h, 10).await;
    expect!(
        "tenzro_agentVoucher",
        json!({ "channel_id": h, "cumulative_amount": "10" }),
    );
    let _ = c
        .auth()
        .update_agent_terms(
            "0x11",
            AGENT,
            json!({ "agent_name": "a" }),
            true,
            |_| async { Ok(json!({ "ok": 1 })) },
        )
        .await;
    expect!(
        "tenzro_updateAgentTerms",
        json!({
            "agent_did": AGENT,
            "delegation": { "completed": true },
            "rotate_tokens": true,
            "authorization": { "ok": 1 },
        }),
    );
    let _ = c
        .auth()
        .revoke_identity(&s, "0x11", AGENT, None, None, |_| async {
            Ok(tenzro_sdk::auth::RootApproval {
                root_public_key: vec![7],
                signature: json!({ "classical": {} }),
            })
        })
        .await;
    let revocation = node.last("tenzro_revokeIdentity");
    assert_eq!(revocation["public_key"], "07".repeat(64));
    assert_eq!(revocation["tx_type"]["RevokeIdentity"]["op"]["did"], AGENT);
    covered.insert("tenzro_revokeIdentity".into());
    let _ = c.auth().refresh_token("r1", &Prover).await;
    expect!("tenzro_refreshToken", json!({ "refresh_token": "r1" }));
    let _ = c.auth().revoke_jwt("j1", "ee", Some("lost")).await;
    expect!(
        "tenzro_revokeJwt",
        json!({ "jti": "j1", "did_envelope": "ee", "reason": "lost" }),
    );
    let _ = c.auth().forget_identity(DID).await;
    expect!("tenzro_forgetIdentity", json!({ "did": DID }));
    let _ = c
        .auth()
        .exchange_token("t", AGENT, "jkt", json!([]), vec![], Some(60))
        .await;
    expect!(
        "tenzro_exchangeToken",
        json!({
            "subject_token": "t",
            "child_bearer_did": AGENT,
            "child_dpop_jkt": "jkt",
            "requested_rar": [],
            "requested_aap_capabilities": [],
            "requested_ttl_secs": 60,
        }),
    );
    let _ = c.auth().introspect_token("t").await;
    expect!("tenzro_introspectToken", json!({ "token": "t" }));
    let _ = c.auth().oauth_discovery().await;
    expect!("tenzro_oauthDiscovery", Value::Null);
    let _ = c.auth().get_payment(Some(&h), None).await;
    expect!(
        "tenzro_getPayment",
        json!({ "pay_ref": h, "payment_id": null }),
    );
    let _ = c
        .auth()
        .list_payments(json!({ "payee": ADDR, "limit": 2 }))
        .await;
    expect!("tenzro_listPayments", json!({ "payee": ADDR, "limit": 2 }));
    let _ = c.auth().get_payee_split(ADDR).await;
    expect!("tenzro_getPayeeSplit", json!({ "payee": ADDR }));

    // Passkeys and custody
    let enroll: EnrollPasskeyParams = serde_json::from_value(json!({
        "passkey_public_key_hex": "aa",
        "credential_id_hex": "cd",
        "ml_dsa_public_key_hex": "ef",
    }))
    .unwrap();
    let _ = c.passkey_rpc().enroll(enroll).await;
    expect!(
        "tenzro_enrollPasskey",
        json!({
            "passkey_public_key_hex": "aa",
            "credential_id_hex": "cd",
            "ml_dsa_public_key_hex": "ef",
            "salt": 0,
        }),
    );
    let _ = c
        .device()
        .challenge(CustodyOperation::BindDevice, DID, "phone")
        .await;
    expect!(
        "tenzro_createCustodyChallenge",
        json!({
            "account_address": hex::encode(DID),
            "operation": "bind_device",
            "target_hex": hex::encode("phone"),
        }),
    );
    let session: CreatePasskeySessionParams =
        serde_json::from_value(json!({ "kind": "enroll" })).unwrap();
    let _ = c.passkey_rpc().create_passkey_session(session).await;
    expect!(
        "tenzro_createPasskeySession",
        json!({ "kind": "enroll", "salt": 0 }),
    );
    let _ = c.passkey_rpc().get_passkey_session("s1").await;
    expect!("tenzro_getPasskeySession", json!({ "session_id": "s1" }));
    let _ = c
        .passkey_rpc()
        .revoke_jwt(RevokeJwtParams {
            jti: "j2".into(),
            did_envelope: "ee".into(),
            reason: None,
        })
        .await;
    expect!(
        "tenzro_revokeJwt",
        json!({ "jti": "j2", "did_envelope": "ee" }),
    );

    // Identity
    let _ = c
        .identity()
        .register_human(&RegisterHumanParams {
            display_name: "Alice".into(),
            public_key: "aa".into(),
            credential_id: "cd".into(),
            proof: json!({ "classical": {} }),
        })
        .await;
    expect!(
        "tenzro_registerIdentity",
        json!({
            "identity_type": "human",
            "display_name": "Alice",
            "public_key": "aa",
            "credential_id": "cd",
            "proof": { "classical": {} },
        }),
    );
    let machine: tenzro_sdk::identity::RegisterMachineParams = serde_json::from_value(json!({
        "controller_did": DID,
        "public_key": "aa",
        "capabilities": ["x"],
    }))
    .unwrap();
    let _ = c.identity().register_machine(machine, &signer).await;
    let m = node.last("tenzro_registerMachineIdentity");
    assert_eq!(m["controller_did"], DID);
    assert_eq!(m["capabilities"], json!(["x"]));
    assert!(m["did_envelope"].is_string());
    covered.insert("tenzro_registerMachineIdentity".into());
    let _ = c.identity().resolve(DID).await;
    expect!("tenzro_resolveIdentity", json!({ "did": DID }));
    let _ = c.identity().resolve_did_document(DID).await;
    expect!("tenzro_resolveDidDocument", json!({ "did": DID }));
    let _ = c.identity().did_services(DID).await;
    expect!("tenzro_getDidServices", json!({ "did": DID }));
    let _ = c.identity().list_identities().await;
    expect!("tenzro_listIdentities", json!([]));
    let _ = c.identity().verify_did_envelope(json!("ee")).await;
    expect!("tenzro_verifyDidEnvelope", json!({ "envelope": "ee" }));
    let _ = c.identity().get_7702delegation("0x01").await;
    expect!("tenzro_get7702Delegation", json!({ "authority": "0x01" }));
    let _ = c.identity().issue_kya_credential(AGENT, Some(60)).await;
    expect!(
        "tenzro_issueKyaCredential",
        json!({ "did": AGENT, "validity_secs": 60 }),
    );
    let _ = c.identity().verify_kya_credential(json!({ "a": 1 })).await;
    expect!(
        "tenzro_verifyKyaCredential",
        json!({ "credential": { "a": 1 } })
    );
    let _ = c
        .identity()
        .verify_node_did_document(json!({ "id": DID }), None)
        .await;
    expect!(
        "tenzro_verifyNodeDidDocument",
        json!({ "document": { "id": DID }, "id": null }),
    );
    let _ = c
        .identity()
        .update_identity(DID, json!({ "kind": "resource" }))
        .await;
    expect!(
        "tenzro_updateIdentity",
        json!({ "did": DID, "update": { "kind": "resource" } }),
    );
    let _ = c.identity().rotate_identity_to_pq(&s, &PqKey, DID, 1).await;
    let r = node.last("tenzro_rotateIdentityToPq");
    assert_eq!(r["did"], DID);
    assert_eq!(r["new_pq_key"], "01010101");
    assert_eq!(r["backend"], "tpm");
    assert_eq!(r["sequence"], 1);
    assert_eq!(r["new_key_signature"], "02020202");
    covered.insert("tenzro_rotateIdentityToPq".into());

    // Devices
    let bind = BindDeviceRequest {
        identity_did: DID.into(),
        label: "phone".into(),
        attestation_object_b64: "YQ".into(),
        client_data_json_b64: "Yw".into(),
        challenge_id: "c1".into(),
        authorization: Some(assertion()),
    };
    let _ = c.device().bind_device(&bind).await;
    expect!("tenzro_bindDevice", serde_json::to_value(&bind).unwrap());
    let _ = c.device().list_bound_devices(DID).await;
    expect!("tenzro_listBoundDevices", json!({ "identity_did": DID }));
    let _ = c
        .device()
        .revoke_bound_device(DID, "Y3JlZA", "c1", &assertion())
        .await;
    expect!(
        "tenzro_revokeBoundDevice",
        json!({
            "identity_did": DID,
            "credential_id": "Y3JlZA",
            "challenge_id": "c1",
            "authorization": serde_json::to_value(assertion()).unwrap(),
        }),
    );
    let _ = c.device().wallet_readiness(DID, None).await;
    expect!(
        "tenzro_walletReadiness",
        json!({ "identity_did": DID, "this_device_credential_id": null }),
    );
    let _ = c
        .device()
        .transfer_machine_ownership(
            AGENT,
            DID,
            "c1",
            &TransferAuthority::Controller {
                controller_did: DID.into(),
                authorization: assertion(),
            },
        )
        .await;
    expect!(
        "tenzro_transferMachineOwnership",
        json!({
            "machine_did": AGENT,
            "new_owner_did": DID,
            "challenge_id": "c1",
            "authority": "controller",
            "controller_did": DID,
            "authorization": serde_json::to_value(assertion()).unwrap(),
        }),
    );
    let _ = c.device().route_payment("100", Some("usdc"), Some(5)).await;
    expect!(
        "tenzro_settlementNetworks",
        json!({ "amount_wei": "100", "asset": "usdc", "tnzo_micro_usd": 5 }),
    );

    // Keystore and machine access
    let _ = c.keystore().get_keystore("0x01", None).await;
    expect!("tenzro_getKeystore", json!({ "account": "0x01" }));
    let _ = c.keystore().resolve_credential("cd", "tenzro.com").await;
    expect!(
        "tenzro_resolveCredential",
        json!({ "credential_id": "cd", "rp_id": "tenzro.com" }),
    );
    let _ = c
        .machine_access()
        .add(json!({ "grantee_did": AGENT }), json!({ "a": 1 }))
        .await;
    expect!(
        "tenzro_addMachineAccess",
        json!({ "grantee_did": AGENT, "authorization": { "a": 1 } }),
    );
    let _ = c.machine_access().list(json!({ "a": 1 })).await;
    expect!(
        "tenzro_listMachineAccess",
        json!({ "authorization": { "a": 1 } })
    );
    let _ = c.machine_access().revoke("g1", json!({ "a": 1 })).await;
    expect!(
        "tenzro_revokeMachineAccess",
        json!({ "grant_id": "g1", "authorization": { "a": 1 } }),
    );

    // Wallet and transactions
    let address = Address::new([3; 32]);
    let _ = c.wallet().get_balance(address.clone()).await;
    expect!("tenzro_getBalance", json!([ADDR]));
    let _ = c.wallet().get_token_balance(address.clone()).await;
    expect!("tenzro_tokenBalance", json!({ "address": ADDR }));
    let _ = c.wallet().get_nonce(address).await;
    expect!("tenzro_getNonce", json!([ADDR]));
    let tx = TypedTransaction::new(TxKind::Transfer, json!({ "amount": 1 })).unwrap();
    let _ = c.transactions().send(&s, &tx).await;
    let p = node.last("tenzro_getSigningPayload");
    assert_eq!(p["tx_type"], json!({ "Transfer": { "amount": 1 } }));
    covered.insert("tenzro_getSigningPayload".into());
    let sent = node.last("tenzro_sendRawTransaction");
    assert_eq!(sent["public_key"], "07".repeat(64));
    assert_eq!(sent["chain_id"], 133801);
    assert_eq!(sent["nonce"], 5);
    covered.insert("tenzro_sendRawTransaction".into());

    // Trust
    let _ = c.trust().submit(&json!({ "a": 1 })).await;
    expect!("tenzro_submitTrustRecord", json!({ "record": { "a": 1 } }));
    let _ = c.trust().verify_credential(&json!({ "a": 1 })).await;
    expect!(
        "tenzro_verifyTrustCredential",
        json!({ "credential": { "a": 1 } })
    );
    let _ = c.trust().credentials(DID).await;
    expect!("tenzro_getTrustCredentials", json!({ "subject": DID }));
    let _ = c.trust().status_list(DID).await;
    expect!("tenzro_getStatusList", json!({ "issuer": DID }));
    let _ = c.trust().operator_policy(DID).await;
    expect!("tenzro_getOperatorPolicy", json!({ "operator": DID }));
    let _ = c.trust().model_provenance("qwen").await;
    expect!("tenzro_getModelProvenance", json!({ "name": "qwen" }));
    let _ = c.trust().host_model(Some("qwen"), None, "/m").await;
    expect!(
        "tenzro_hostModel",
        json!({ "name": "qwen", "root": null, "path": "/m" }),
    );
    let _ = c.trust().scan_model_files(None, None, "/m").await;
    expect!(
        "tenzro_scanModelFiles",
        json!({ "name": null, "root": null, "path": "/m" }),
    );
    let _ = c.trust().verify_model_files(None, Some(&h), "/m").await;
    expect!(
        "tenzro_verifyModelFiles",
        json!({ "name": null, "root": h, "path": "/m" }),
    );
    let _ = c
        .trust()
        .publish_tee_measurement(&s, json!({ "vendor": "IntelTdx" }), &h, &[1, 2])
        .await;
    let t = node.last("tenzro_publishTeeMeasurement");
    assert_eq!(t["report"], json!({ "vendor": "IntelTdx" }));
    assert_eq!(t["nonce"], h);
    assert!(t["publisher_key_hex"].is_string() && t["signature_hex"].is_string());
    covered.insert("tenzro_publishTeeMeasurement".into());

    // Governance
    let _ = c
        .governance()
        .list_proposals(5, None, Some("policy_update"))
        .await;
    expect!(
        "tenzro_listProposals",
        json!({ "limit": 5, "before": null, "kind": "policy_update" }),
    );
    let _ = c.governance().get_proposal(&h).await;
    assert!(node.last("tenzro_getProposal")["proposal_id"].is_string());
    covered.insert("tenzro_getProposal".into());
    let _ = c.governance().get_treasury_accounts().await;
    expect!("tenzro_getTreasuryAccounts", json!({}));
    let _ = c.governance().get_guardian_state(Some(ADDR)).await;
    expect!("tenzro_getGuardianState", json!({ "address": ADDR }));
    let _ = c.governance().get_voting_power(ADDR).await;
    expect!("tenzro_getVotingPower", json!({ "address": ADDR }));
    let _ = c.governance().get_policy("economic_policy").await;
    expect!("tenzro_getPolicy", json!({ "kind": "economic_policy" }));
    let _ = c.governance().get_governance_receipt(&h).await;
    expect!("tenzro_getGovernanceReceipt", json!({ "proposal_id": h }));
    let _ = c
        .governance()
        .decode_action(json!({ "tx_type": { "Transfer": { "amount": 1 } } }))
        .await
        .unwrap();
    expect!(
        "tenzro_decodeAction",
        json!({ "transaction": { "tx_type": { "Transfer": { "amount": 1 } } } }),
    );
    let _ = c.governance().get_upgrade_readiness(&h).await;
    expect!("tenzro_getUpgradeReadiness", json!({ "code_hash": h }));
    let _ = c.governance().get_network_params(Some("fee_bps")).await;
    expect!("tenzro_getNetworkParams", json!({ "key": "fee_bps" }));
    let _ = c.governance().list_levers(Some("bridge")).await;
    expect!("tenzro_listLevers", json!({ "area": "bridge" }));
    let _ = c.governance().signal_upgrade_ready(&h).await;
    expect!("tenzro_signalUpgradeReady", json!({ "code_hash": h }));
    let _ = c.funding().get_grant(&format!("0x{h}")).await;
    expect!("tenzro_getGrant", json!({ "grant_id": h }));

    // Agents
    let _ = c
        .agent()
        .discover_models(Some("text"), Some(true), Some("q"))
        .await;
    expect!(
        "tenzro_discoverModels",
        json!({ "modality": "text", "serving_only": true, "query": "q" }),
    );
    let _ = c.agent().get_audit_commit("0xaa", Some(3)).await;
    expect!(
        "tenzro_getAgentAuditCommit",
        json!({ "committer": "0xaa", "epoch": 3 }),
    );
    let _ = c.agent().verify_audit_attestation("0xaa", 3).await;
    expect!(
        "tenzro_verifyAgentAuditAttestation",
        json!({ "committer": "0xaa", "epoch": 3 }),
    );
    let _ = c.agent().get_quarantine(AGENT).await;
    expect!("tenzro_getAgentQuarantine", json!({ "agent_did": AGENT }));
    let _ = c.agent().resolve_agent_key(AGENT, "k1").await;
    expect!(
        "tenzro_resolveAgentKey",
        json!({ "agent_did": AGENT, "keyid": "k1" }),
    );
    let _ = c.agent().get_bridge_circuit("eip155:1", "ccip").await;
    expect!(
        "tenzro_getBridgeCircuit",
        json!({ "source_chain": "eip155:1", "adapter": "ccip" }),
    );
    let pack: tenzro_sdk::agent::EvidencePackRequest =
        serde_json::from_value(json!({ "agent_did": AGENT })).unwrap();
    let _ = c.agent().export_evidence_pack(&pack).await;
    expect!("tenzro_exportEvidencePack", json!({ "agent_did": AGENT }));
    let _ = c.agent().flag_agent_audit(2, json!([{ "a": 1 }])).await;
    expect!(
        "tenzro_flagAgentAudit",
        json!({ "epoch": 2, "findings": [{ "a": 1 }] }),
    );
    let _ = c.agent().record_agent_audit_session(&h, &h, 4).await;
    expect!(
        "tenzro_recordAgentAuditSession",
        json!({ "session_id": h, "mmr_root": h, "count": 4 }),
    );
    let _ = c.agent().get_kill_switch_receipt(&h).await;
    expect!("tenzro_getKillSwitchReceipt", json!({ "receipt_id": h }));
    let _ = c
        .agent()
        .list_kill_switch_by_agent(AGENT, PageRequest::after("1:0:0"))
        .await;
    expect!(
        "tenzro_listKillSwitchByAgent",
        json!({ "agent_did": AGENT, "from_cursor": "1:0:0" }),
    );
    let page = PageRequest {
        from_height: Some(10),
        limit: Some(3),
        ..PageRequest::default()
    };
    let _ = c.agent().list_kill_switch_by_controller(DID, page).await;
    expect!(
        "tenzro_listKillSwitchByController",
        json!({ "controller_did": DID, "from_height": 10, "limit": 3 }),
    );
    let _ = c.agent_payments().get_agent_bond(AGENT).await;
    expect!("tenzro_getAgentBond", json!({ "agent_did": AGENT }));
    let _ = c.agent_payments().list_agent_bonds_by_controller(DID).await;
    expect!(
        "tenzro_listAgentBondsByController",
        json!({ "controller_did": DID }),
    );
    let _ = c.agent_payments().get_terms(AGENT).await;
    expect!("tenzro_getAgentTerms", json!({ "agent_did": AGENT }));

    // Agent accounts on other chains
    let _ = c.agent_accounts().accounts(AGENT).await;
    expect!("tenzro_agentAccounts", json!({ "did": AGENT }));
    let _ = c
        .agent_accounts()
        .request_grant("eip155:8453", json!({ "a": 1 }), None)
        .await;
    expect!(
        "tenzro_requestRemoteGrant",
        json!({ "chain": "eip155:8453", "grant": { "a": 1 } }),
    );
    let _ = c
        .agent_accounts()
        .grant_proof(AGENT, "eip155:8453", Some(2))
        .await;
    expect!(
        "tenzro_getAgentGrantProof",
        json!({ "did": AGENT, "chain": "eip155:8453", "checkpoint": 2 }),
    );
    let _ = c
        .agent_accounts()
        .build_action(AGENT, "eip155:8453", 1, json!({ "a": 1 }))
        .await;
    expect!(
        "tenzro_buildRemoteAction",
        json!({ "did": AGENT, "chain": "eip155:8453", "nonce": 1, "action": { "a": 1 } }),
    );
    let _ = c
        .agent_accounts()
        .wallet_consent(AGENT, "eip155:8453", 7, "0x01", 100, None)
        .await;
    expect!(
        "tenzro_agentWalletConsent",
        json!({
            "did": AGENT,
            "chain": "eip155:8453",
            "agent_id": 7,
            "owner": "0x01",
            "deadline": 100,
            "registry": null,
        }),
    );
    let _ = c
        .agent_accounts()
        .sign_action("eip155:8453", 1, json!({ "a": 1 }))
        .await;
    expect!(
        "tenzro_signRemoteAction",
        json!({ "chain": "eip155:8453", "nonce": 1, "action": { "a": 1 } }),
    );
    let _ = c
        .agent_accounts()
        .sign_channel_voucher("eip155:8453", 3, 10)
        .await;
    expect!(
        "tenzro_signRemoteChannelVoucher",
        json!({ "chain": "eip155:8453", "channel_id": 3, "cumulative_amount": "10" }),
    );

    // Bridge
    let _ = c.bridge().list_routes().await;
    expect!("tenzro_listBridgeRoutes", json!({}));
    let _ = c.bridge().get_route("ccip", "eip155:1").await;
    expect!(
        "tenzro_getBridgeRoute",
        json!({ "adapter": "ccip", "source_chain": "eip155:1" }),
    );
    let _ = c.bridge().get_outbound("ccip", "eip155:1", 4).await;
    expect!(
        "tenzro_getBridgeOutbound",
        json!({ "adapter": "ccip", "source_chain": "eip155:1", "sequence": 4 }),
    );
    let _ = c.bridge().get_outflow().await;
    expect!("tenzro_getBridgeOutflow", json!({}));
    let _ = c.bridge().get_exit(9).await;
    expect!("tenzro_getBridgeExit", json!({ "id": 9 }));
    let _ = c
        .bridge_fee()
        .quote(tenzro_sdk::bridge_fee::QuoteBridgeFeeRequest {
            adapter: "ccip".into(),
            dest_chain: "eip155:1".into(),
            native_fee_smallest_unit: "5".into(),
        })
        .await;
    expect!(
        "tenzro_quoteBridgeFeeInTnzo",
        json!({ "adapter": "ccip", "dest_chain": "eip155:1", "native_fee_smallest_unit": "5" }),
    );

    // Payments
    let _ = c
        .payment()
        .create_challenge("/r", 5, "TNZO", "x402", None)
        .await;
    expect!(
        "tenzro_createPaymentChallenge",
        json!({ "resource": "/r", "amount": "5", "asset": "TNZO", "protocol": "x402" }),
    );
    let _ = c.payment().quote(1000, &["TNZO"]).await;
    expect!("tenzro_quotePayment", json!({ "usd_e6": 1000, "accept": ["TNZO"] }));
    let credential: tenzro_sdk::payment::PaymentCredential = serde_json::from_value(json!({
        "credential_id": "k1",
        "challenge_id": "c1",
        "protocol": "mpp",
        "payer_did": DID,
        "payer_address": ADDR,
        "amount": 5,
        "asset": "TNZO",
        "signature": {},
        "extra": {},
    }))
    .unwrap();
    let _ = c.payment().verify_payment(&credential).await;
    assert_eq!(
        node.last("tenzro_verifyPayment")["credential"]["challenge_id"],
        "c1"
    );
    covered.insert("tenzro_verifyPayment".into());
    let _ = c
        .payment()
        .mirror_settlement(json!({ "a": 1 }), json!([]), true)
        .await;
    expect!(
        "tenzro_mirrorSettlement",
        json!({ "interaction": { "a": 1 }, "targets": [], "primary_committed": true }),
    );
    let _ = c.payment().set_settlement_preference(&s, DID, "tnzo").await;
    let pref = node.last("tenzro_setSettlementPreference");
    assert_eq!(pref["payee_did"], DID);
    assert_eq!(pref["asset"], "tnzo");
    assert_eq!(pref["public_key"], "07".repeat(64));
    assert_eq!(pref["signature"]["classical"]["form"], "raw");
    assert!(pref["timestamp_ms"].is_i64());
    covered.insert("tenzro_setSettlementPreference".into());
    let permit = tenzro_sdk::permit2::Permit2VerifyAndConsumeRequest {
        owner: "0x01".into(),
        signature: "0x02".into(),
        witness: Some(h.clone()),
        witness_type_name: Some("Order".into()),
        witness_type_string: Some("Order(uint256 id)".into()),
        ..Default::default()
    };
    let _ = c.permit2().verify_and_consume(permit.clone()).await;
    let w = node.last("tenzro_permit2VerifyAndConsume");
    assert_eq!(w["witness_type_name"], "Order");
    assert_eq!(w["owner"], "0x01");
    covered.insert("tenzro_permit2VerifyAndConsume".into());
    let _ = c.permit2().nonce_used("0x01", "0x02").await;
    expect!(
        "tenzro_permit2NonceUsed",
        json!({ "owner": "0x01", "nonce": "0x02" }),
    );

    // Settlement
    let _ = c
        .settlement()
        .settle(SettlementRequest {
            payee: ADDR.into(),
            amount: 5,
            payment: json!({ "a": 1 }),
        })
        .await;
    expect!(
        "tenzro_settle",
        json!({ "payee": ADDR, "amount": "5", "payment": { "a": 1 } }),
    );
    let _ = c.settlement().get_escrow([0xab; 32]).await;
    expect!("tenzro_getEscrow", json!({ "escrow_id": format!("0x{h}") }));
    let _ = c
        .settlement()
        .list_escrows_by_payer(ADDR, PageRequest::after("1:0:0"))
        .await;
    expect!(
        "tenzro_listEscrowsByPayer",
        json!({ "payer": ADDR, "from_cursor": "1:0:0" }),
    );
    let _ = c
        .settlement()
        .list_escrows_by_payee(ADDR, PageRequest::default())
        .await;
    expect!("tenzro_listEscrowsByPayee", json!({ "payee": ADDR }));
    let _ = c.settlement().open_payment_channel(&h).await;
    expect!("tenzro_openPaymentChannel", json!({ "channel_id": h }));
    let _ = c.settlement().close_payment_channel(&s, &h).await;
    let close = node.last("tenzro_closePaymentChannel");
    assert_eq!(close["channel_id"], h);
    assert_eq!(close["public_key"], "07".repeat(64));
    assert_eq!(close["signature"]["classical"]["form"], "raw");
    assert!(close["timestamp_ms"].is_i64());
    covered.insert("tenzro_closePaymentChannel".into());
    let _ = c.settlement().get_meter_bond(&h).await;
    expect!("tenzro_getMeterBond", json!({ "meter_id": h }));
    let _ = c.settlement().redeem_sealed_delivery(&h, None).await;
    expect!(
        "tenzro_redeemSealedDelivery",
        json!({ "escrow_id": h, "network_escrow_id": null }),
    );
    let _ = c
        .settlement()
        .update_payment_channel(json!({ "a": 1 }), "5")
        .await;
    expect!(
        "tenzro_updatePaymentChannel",
        json!({ "voucher": { "a": 1 }, "charge": "5" }),
    );
    let _ = c.settlement().get_settlement_preference(DID).await;
    expect!(
        "tenzro_getSettlementPreference",
        json!({ "payee_did": DID })
    );
    let split: tenzro_sdk::settle::SplitRule =
        serde_json::from_value(json!({ "version": 1, "lines": [] })).unwrap();
    let _ = c.settle().preview_split(100, &split, 0).await;
    expect!(
        "tenzro_previewSplit",
        json!({ "gross": "100", "split": { "version": 1, "lines": [] }, "network_fees": "0" }),
    );
    let _ = c
        .settle()
        .submit_reconciliation("ccip", "eip155:1", json!([]), &[0xab, 0xcd])
        .await;
    expect!(
        "tenzro_submitReconciliation",
        json!({ "adapter": "ccip", "chain": "eip155:1", "entries": [], "checkpoint": "abcd" }),
    );
    let _ = c.settle().get_reconciliation("ccip", "eip155:1").await;
    expect!(
        "tenzro_getReconciliation",
        json!({ "adapter": "ccip", "chain": "eip155:1" }),
    );
    let _ = c.settle().list_mismatches("ccip", "eip155:1").await;
    expect!(
        "tenzro_listMismatches",
        json!({ "adapter": "ccip", "chain": "eip155:1" }),
    );
    let _ = c.settle().get_netting_batch(&h, Some(2), None).await;
    expect!(
        "tenzro_getNettingBatch",
        json!({ "asset": h, "seq": 2, "participant": null }),
    );
    let _ = c.settle().get_plan(&h).await;
    expect!("tenzro_getPlan", json!({ "plan_id": h }));
    let _ = c.settle().get_decision(&h).await;
    expect!("tenzro_getPlanDecision", json!({ "plan_id": h }));
    let _ = c.settle().get_leg_receipt(&h, 1).await;
    expect!("tenzro_getLegReceipt", json!({ "plan_id": h, "index": 1 }),);
    let _ = c.settle().list_plans(None, Some("open"), Some(3)).await;
    expect!(
        "tenzro_listPlans",
        json!({ "payer": null, "status": "open", "limit": 3 }),
    );

    assert_eq!(covered.len(), 135, "covered: {covered:?}");
}

#[test]
fn the_owner_signed_close_message_is_the_nodes() {
    let id = [0xab; 32];
    let m = tenzro_sdk::owner_request_message("tenzro_closePaymentChannel", &id, 1000);
    let mut want = b"tenzro/rpc-owner/v1\0tenzro_closePaymentChannel\0".to_vec();
    want.extend_from_slice(&id);
    want.extend_from_slice(&1000i64.to_le_bytes());
    assert_eq!(m, want);
}

#[test]
fn typed_reads_decode_the_nodes_shapes() {
    let receipt: tenzro_sdk::KillSwitchReceipt = serde_json::from_value(json!({
        "receipt_id": "aa",
        "action": "pause",
        "agent_did": AGENT,
        "controller_did": DID,
        "reason_code": 3,
        "reason_text": null,
        "evidence_hash": null,
        "slash_bps": null,
        "cascade": null,
        "frozen_at_block": 10,
        "timestamp": 1000,
        "cursor": "10:0:0",
    }))
    .unwrap();
    assert_eq!(receipt.cursor.as_deref(), Some("10:0:0"));
    let page: tenzro_sdk::KillSwitchPage = serde_json::from_value(json!({
        "agent_did": AGENT,
        "receipts": [],
        "cursor": null,
    }))
    .unwrap();
    assert!(page.cursor.is_none());
    let log: tenzro_sdk::AuditLog = serde_json::from_value(json!({
        "count": 1,
        "records": [{
            "record": {
                "seq": 0,
                "prev": "00",
                "at": "2026-10-19T00:00:00.000Z",
                "node": null,
                "chain_id": 133801,
                "entry": { "kind": "opened", "data": { "version": "0.9.0", "after_unreadable_line": false } },
            },
            "hash": "aa",
        }],
    }))
    .unwrap();
    assert_eq!(log.records[0].record.entry.kind, "opened");
    let v: tenzro_sdk::AuditVerification = serde_json::from_value(json!({
        "ok": true,
        "records": 1,
        "segments": ["audit.log"],
        "first_seq": 0,
        "last_seq": 0,
        "head_hash": "aa",
        "checkpoints": 0,
        "signed_checkpoints": 0,
        "unsigned_checkpoints": 0,
        "problems": [],
    }))
    .unwrap();
    assert!(v.ok);
    let t: tenzro_sdk::TreasuryAccounts = serde_json::from_value(json!({
        "did": "did:tenzro:treasury",
        "tenzro": "aa",
        "accounts": [
            { "caip2": "eip155:1", "address": "0x01", "caip10": "eip155:1:0x01", "grant": null },
            { "caip2": "solana:x", "error": "no adapter" },
        ],
        "bitcoin": "deposit route",
    }))
    .unwrap();
    assert_eq!(t.accounts.len(), 2);
    let close: tenzro_sdk::ChannelClose = serde_json::from_value(json!({
        "channel_id": "aa", "status": "closed", "claim_due": "5",
    }))
    .unwrap();
    assert_eq!(close.claim_due.as_deref(), Some("5"));
}
