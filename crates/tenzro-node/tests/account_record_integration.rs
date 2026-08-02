//! A wallet survives the node it was created on.
//!
//! The private keys were never at risk — they live in the users' devices. What
//! is at risk is the *list* of which devices those are, which lived in one
//! node's database. These tests take that list from a node that has it to a
//! node that has never seen the account, and then try to poison it.
//!
//! The poisoning case is the one that matters. Replicating custody state is
//! exactly the shape of thing that reopens an account-takeover over the network
//! if a peer can simply assert "here are Alice's devices". Acceptance has to be
//! decided by the record's own chain, not by who offered it.

use serde_json::{Value, json};
use std::sync::Arc;
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tokio::sync::broadcast;

struct TestNode {
    base_url: String,
    shutdown: broadcast::Sender<()>,
    handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
    _tmp: tempfile::TempDir,
    client: reqwest::Client,
}

impl TestNode {
    async fn boot() -> Self {
        let tmp = tempfile::tempdir().expect("temp dir");
        let config = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let mut node = TenzroNode::new(config).await.expect("node creation");
        node.start().await.expect("node start");
        let node = Arc::new(node);

        let (shutdown, shutdown_rx) = broadcast::channel::<()>(1);
        let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
        let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string());
        let handle =
            tokio::spawn(
                async move { rpc.start_with_shutdown_and_addr(shutdown_rx, addr_tx).await },
            );
        let addr = addr_rx.await.expect("bound address");

        Self {
            base_url: format!("http://{addr}"),
            shutdown,
            handle,
            _tmp: tmp,
            client: reqwest::Client::new(),
        }
    }

    async fn rpc(&self, method: &str, params: Value) -> Value {
        self.client
            .post(&self.base_url)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
            .send()
            .await
            .expect("HTTP request")
            .json::<Value>()
            .await
            .expect("JSON parse")
    }

    async fn enroll(&self, seed: u8, cred: u8) -> (String, String) {
        let hex_of =
            |b: u8, n: usize| -> String { std::iter::repeat_n(format!("{b:02x}"), n).collect() };
        let resp = self
            .rpc(
                "tenzro_enrollPasskey",
                json!({
                    "display_name": "Owner laptop",
                    "passkey_public_key_hex":
                        format!("04{}{}", hex_of(seed, 32), hex_of(seed.wrapping_add(1), 32)),
                    "credential_id_hex": hex_of(cred, 16),
                    "ml_dsa_public_key_hex": hex_of(seed.wrapping_add(2), 1952),
                }),
            )
            .await;
        let account = resp["result"]["smart_account_address"]
            .as_str()
            .unwrap_or_else(|| panic!("enroll failed: {resp}"))
            .to_string();
        (account, hex_of(cred, 16))
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }
}

// ---------------------------------------------------------------------------
// Publication
// ---------------------------------------------------------------------------

/// Enrolling publishes a genesis record. Without this, a wallet is unrecoverable
/// from the moment it is created.
#[tokio::test]
async fn enrolling_publishes_a_record() {
    let n = TestNode::boot().await;
    let (account, credential) = n.enroll(0x11, 0xaa).await;

    let got = n
        .rpc(
            "tenzro_getAccountRecord",
            json!({ "account_address": account }),
        )
        .await;
    let record = &got["result"]["record"];
    assert_eq!(record["version"], 0, "{got}");
    assert_eq!(record["account_address"], account);
    assert!(
        record["owner_did"]
            .as_str()
            .unwrap_or_default()
            .starts_with("did:tenzro:human:"),
        "the record must name its owner: {record}"
    );

    let creds = record["credentials"].as_array().expect("credentials");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0]["credential_id_hex"], credential);
    assert!(
        got["result"]["commitment"]
            .as_str()
            .unwrap_or_default()
            .starts_with("0x"),
        "a record must be committable so it can be anchored"
    );

    // Public material only. A record that carried anything signable would
    // defeat the point of keys living in devices.
    let serialized = serde_json::to_string(record).expect("serializes");
    assert!(!serialized.contains("private"), "{serialized}");
    assert!(!serialized.contains("secret"), "{serialized}");
    n.shutdown().await;
}

#[tokio::test]
async fn an_unknown_account_reports_that_it_is_unknown() {
    let n = TestNode::boot().await;
    let got = n
        .rpc(
            "tenzro_getAccountRecord",
            json!({ "account_address": "0xdeadbeef" }),
        )
        .await;
    assert!(got.get("result").is_none(), "{got}");
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// Recovery onto a node that never held the account
// ---------------------------------------------------------------------------

/// The whole point: the wallet outlives its origin node.
#[tokio::test]
async fn a_record_transfers_to_a_node_that_never_saw_the_account() {
    let origin = TestNode::boot().await;
    let (account, _) = origin.enroll(0x21, 0xbb).await;

    let record = origin
        .rpc(
            "tenzro_getAccountRecord",
            json!({ "account_address": account }),
        )
        .await["result"]["record"]
        .clone();

    // A different node, with no knowledge of this account at all.
    let fresh = TestNode::boot().await;
    assert!(
        fresh
            .rpc(
                "tenzro_getAccountRecord",
                json!({ "account_address": account })
            )
            .await
            .get("result")
            .is_none(),
        "the fresh node should not know this account yet"
    );

    let published = fresh
        .rpc(
            "tenzro_publishAccountRecord",
            json!({ "record": record, "signing_credential_id_hex": "" }),
        )
        .await;
    assert_eq!(published["result"]["accepted"], true, "{published}");

    // And it now answers for the account.
    let recovered = fresh
        .rpc(
            "tenzro_getAccountRecord",
            json!({ "account_address": account }),
        )
        .await;
    assert_eq!(recovered["result"]["record"]["version"], 0, "{recovered}");
    assert_eq!(recovered["result"]["record"]["account_address"], account);

    origin.shutdown().await;
    fresh.shutdown().await;
}

// ---------------------------------------------------------------------------
// Poisoning
// ---------------------------------------------------------------------------

/// The case that decides whether replication is safe at all. An attacker offers
/// a record naming their own device — signed by their own device. If a node
/// accepts it, the wallet is theirs everywhere the record spreads.
#[tokio::test]
async fn a_forged_successor_is_rejected() {
    let n = TestNode::boot().await;
    let (account, owner_cred) = n.enroll(0x31, 0xcc).await;

    let genesis = n
        .rpc(
            "tenzro_getAccountRecord",
            json!({ "account_address": account }),
        )
        .await["result"]
        .clone();
    let commitment = genesis["commitment"]
        .as_str()
        .expect("commitment")
        .to_string();

    // Version 1, replacing the owner's device with the attacker's.
    let forged = json!({
        "account_address": account,
        "owner_did": genesis["record"]["owner_did"],
        "version": 1,
        "previous_commitment_hex": commitment,
        "credentials": [{
            "credential_id_hex": "ee".repeat(16),
            "p256_public_key_hex": "99".repeat(64),
        }],
        "policy": "single_credential",
        "guardians": [],
        "published_at_ms": 2,
    });

    let attempt = n
        .rpc(
            "tenzro_publishAccountRecord",
            json!({
                "record": forged,
                "signing_credential_id_hex": "ee".repeat(16),
            }),
        )
        .await;
    assert!(
        attempt.get("result").is_none(),
        "a record signed by a device that was never on the account was accepted: {attempt}"
    );
    let msg = attempt["error"]["message"].as_str().unwrap_or_default();
    assert!(msg.contains("not an authority"), "{msg}");

    // The held record is untouched — the owner's device still signs.
    let after = n
        .rpc(
            "tenzro_getAccountRecord",
            json!({ "account_address": account }),
        )
        .await;
    assert_eq!(after["result"]["record"]["version"], 0);
    let creds = after["result"]["record"]["credentials"]
        .as_array()
        .expect("credentials");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0]["credential_id_hex"], owner_cred);
    n.shutdown().await;
}

/// "Start again from scratch" must not be a takeover primitive.
#[tokio::test]
async fn a_second_genesis_cannot_replace_an_existing_account() {
    let n = TestNode::boot().await;
    let (account, owner_cred) = n.enroll(0x41, 0xdd).await;

    let replacement = json!({
        "account_address": account,
        "owner_did": "did:tenzro:human:attacker",
        "version": 0,
        "credentials": [{
            "credential_id_hex": "ff".repeat(16),
            "p256_public_key_hex": "88".repeat(64),
        }],
        "policy": "single_credential",
        "guardians": [],
        "published_at_ms": 3,
    });

    let attempt = n
        .rpc(
            "tenzro_publishAccountRecord",
            json!({ "record": replacement, "signing_credential_id_hex": "ff".repeat(16) }),
        )
        .await;
    assert!(attempt.get("result").is_none(), "{attempt}");

    let after = n
        .rpc(
            "tenzro_getAccountRecord",
            json!({ "account_address": account }),
        )
        .await;
    assert_eq!(
        after["result"]["record"]["credentials"][0]["credential_id_hex"], owner_cred,
        "a second genesis replaced the account's devices"
    );
    n.shutdown().await;
}

/// A record whose commitment does not follow the one held is a fork, not an
/// update — accepting it would mean two divergent histories of who can sign.
#[tokio::test]
async fn a_record_naming_the_wrong_predecessor_is_rejected() {
    let n = TestNode::boot().await;
    let (account, _) = n.enroll(0x51, 0xee).await;
    let owner_did = n
        .rpc(
            "tenzro_getAccountRecord",
            json!({ "account_address": account }),
        )
        .await["result"]["record"]["owner_did"]
        .clone();

    let forked = json!({
        "account_address": account,
        "owner_did": owner_did,
        "version": 1,
        "previous_commitment_hex": format!("0x{}", "00".repeat(32)),
        "credentials": [{
            "credential_id_hex": "ee".repeat(16),
            "p256_public_key_hex": "99".repeat(64),
        }],
        "policy": "single_credential",
        "guardians": [],
        "published_at_ms": 4,
    });

    let attempt = n
        .rpc(
            "tenzro_publishAccountRecord",
            json!({ "record": forked, "signing_credential_id_hex": "ee".repeat(16) }),
        )
        .await;
    assert!(attempt.get("result").is_none(), "{attempt}");
    n.shutdown().await;
}
