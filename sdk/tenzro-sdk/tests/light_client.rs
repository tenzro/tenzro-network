//! The light client over the SDK's node connection (feature `light`): a node
//! on a local port answers from a test committee, and the client accepts
//! only what that committee certified.

use std::sync::Arc;

use serde_json::{Value, json};
use tenzro_light::identity;
use tenzro_light::identity::{IdentityHead, IdentityKeyEpoch, IdentityKeyHistory};
use tenzro_light::testkit::{CHAIN_ID, GENESIS, Net, State};
use tenzro_sdk::TenzroClient;
use tenzro_sdk::error::SdkError;
use tenzro_sdk::light::{Checkpoint, Clock, TrustAnchor};
use tenzro_types::identity::{RegisterIdentityPayload, RegistrationProof};
use tenzro_types::primitives::Address;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DID: &str = "did:tenzro:human:7f1c";

fn hex_bincode<T: serde::Serialize>(v: &T) -> String {
    format!("0x{}", hex::encode(bincode::serialize(v).unwrap()))
}

fn record(key: u8) -> Vec<u8> {
    serde_json::to_vec(&RegisterIdentityPayload {
        did: DID.to_string(),
        identity_type: "human".into(),
        display_name: "A".into(),
        controller_pubkey: vec![key; 65],
        key_type: "P256".into(),
        wallet_id: "w".into(),
        wallet_address: Address::new([9; 32]),
        pq_verifying_key: vec![key; 1952],
        metadata: Default::default(),
        proof: RegistrationProof::Hardware {
            signature: Default::default(),
        },
    })
    .unwrap()
}

fn head_after_one() -> IdentityHead {
    IdentityHead::default().advanced(DID, b"IdentityKeyUpdated", b"k")
}

/// A node of one epoch whose newest certified checkpoint commits a state
/// holding one identity with keys `key` and one recorded key change.
struct OneEpoch {
    net: Net,
    checkpoint: Checkpoint,
    state: State,
}

impl OneEpoch {
    fn new(key: u8) -> Self {
        let net = Net::new(4);
        let mut checkpoint = net.checkpoint(5);
        let slot = identity::system_slot(&identity::registration_slot(DID));
        let id = record(key);
        let keys_slot = identity::system_slot(&identity::key_history_slot(DID));
        let keys = serde_json::to_vec(&IdentityKeyHistory {
            epochs: vec![IdentityKeyEpoch {
                version: 1,
                ed25519: [key; 32],
                ml_dsa: vec![key; 1952],
                effective_from_ms: checkpoint.timestamp_ms - 1_000,
                compromised_from_ms: None,
                next_commitment: None,
            }],
        })
        .unwrap();
        let head_slot = identity::system_slot(&identity::head_slot(DID));
        let head = serde_json::to_vec(&head_after_one()).unwrap();
        let ns = identity::STATE_NAMESPACE;
        let state = State::new(
            checkpoint.state_height,
            &[
                (ns, &slot, &id),
                (ns, &keys_slot, &keys),
                (ns, &head_slot, &head),
            ],
        );
        checkpoint.state_root = state.root();
        OneEpoch {
            net,
            checkpoint,
            state,
        }
    }

    fn clock(&self) -> Clock {
        Clock {
            now_ms: self.checkpoint.timestamp_ms + 1_000,
            max_age_ms: 60_000,
            max_ahead_ms: 5_000,
        }
    }

    fn answer(&self, method: &str, params: &Value) -> Value {
        match method {
            "tenzro_getCommittee" => json!({ "members": hex_bincode(&self.net.members) }),
            "tenzro_getCheckpointCertificate" => {
                let (cert, sessions) = self.net.certify(&self.checkpoint, &[0, 1, 2]);
                json!({
                    "epoch": 0,
                    "certificate": hex_bincode(&cert),
                    "sessions": hex_bincode(&sessions),
                })
            }
            "tenzro_getStateProof" => self.state.reply(params).unwrap(),
            other => json!({ "ok": other }),
        }
    }
}

/// Serves JSON-RPC on a local port from `node`; returns its URL.
async fn serve(node: Arc<OneEpoch>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let node = node.clone();
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
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                while buf.len() < body_start + len {
                    let n = sock.read(&mut chunk).await.unwrap();
                    buf.extend_from_slice(&chunk[..n]);
                }
                let request: Value = serde_json::from_slice(&buf[body_start..]).unwrap();
                let result =
                    node.answer(request["method"].as_str().unwrap_or(""), &request["params"]);
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

fn anchor(node: &OneEpoch) -> TrustAnchor {
    TrustAnchor {
        chain_id: CHAIN_ID,
        genesis_hash: GENESIS,
        epoch: 0,
        committee_root: node.net.anchor().committee_root,
    }
}

#[tokio::test]
async fn a_client_syncs_and_proves_an_identity_s_keys() {
    let node = Arc::new(OneEpoch::new(1));
    let client = TenzroClient::new(&serve(node.clone()).await).await.unwrap();
    let mut lc = client.light_client(&anchor(&node)).await.unwrap();
    let clock = node.clock();

    let cp = lc.sync(&clock).await.unwrap();
    assert_eq!(cp, node.checkpoint);
    let id = lc.resolve_identity(DID, &clock).await.unwrap().unwrap();
    assert_eq!(id.controller_key, vec![1; 65]);
    assert!(!id.revoked);
    let history = lc.key_history(DID, &clock).await.unwrap();
    assert_eq!(history.head, head_after_one());
    let t = node.checkpoint.timestamp_ms;
    assert_eq!(history.key_at(t - 500).unwrap().ed25519, [1; 32]);
    assert!(history.key_at(t - 1_001).is_none());
    assert!(
        lc.resolve_identity("did:tenzro:human:nobody", &clock)
            .await
            .unwrap()
            .is_none()
    );

    let saved = lc.save();
    let back = tenzro_sdk::light::LightClient::restore(
        Arc::new(
            tenzro_sdk::rpc::RpcClient::new(
                &serve(node.clone()).await,
                std::time::Duration::from_secs(5),
                None,
            )
            .unwrap(),
        ),
        &saved,
        CHAIN_ID,
        &GENESIS,
        cp.index,
    )
    .unwrap();
    assert_eq!(back.latest(), Some(&cp));
}

#[tokio::test]
async fn members_that_do_not_hash_to_the_anchor_are_refused() {
    let node = Arc::new(OneEpoch::new(1));
    let client = TenzroClient::new(&serve(node.clone()).await).await.unwrap();
    let mut wrong = anchor(&node);
    wrong.committee_root = [7; 32];
    assert!(matches!(
        client.light_client(&wrong).await,
        Err(SdkError::Light(_))
    ));
}

#[tokio::test]
async fn nothing_is_read_before_a_checkpoint_is_certified() {
    let node = Arc::new(OneEpoch::new(1));
    let client = TenzroClient::new(&serve(node.clone()).await).await.unwrap();
    let lc = client.light_client(&anchor(&node)).await.unwrap();
    assert!(lc.resolve_identity(DID, &node.clock()).await.is_err());
}

#[tokio::test]
async fn an_old_checkpoint_is_refused_against_the_caller_s_clock() {
    let node = Arc::new(OneEpoch::new(1));
    let client = TenzroClient::new(&serve(node.clone()).await).await.unwrap();
    let mut lc = client.light_client(&anchor(&node)).await.unwrap();
    let late = Clock {
        now_ms: node.checkpoint.timestamp_ms + 3_600_000,
        ..node.clock()
    };
    assert!(matches!(lc.sync(&late).await, Err(SdkError::Light(_))));
}
