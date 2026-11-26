//! The app transport end to end on a live node: devices sign in with the
//! node's own access tokens and exchange a stream through it. A node starts
//! only with its machine identity key in hardware, so these run on a machine
//! that has one (`--ignored`).
#![cfg(feature = "app-transport")]

mod dpop_bearer;
mod passkey_holder;

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use serde_json::{Value, json};
use tenzro_crypto::pq::ml_dsa_verify;
use tenzro_iroh::app_stream::{
    Frame, Usage, WELCOME_PQ_CONTEXT, read_frame, sign_in_htu, welcome_digest, write_frame,
};
use tenzro_node::config::AppTransportConfig;
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast;
use tokio::time::timeout;
use wtransport::endpoint::endpoint_side::Client;
use wtransport::tls::Sha256Digest;
use wtransport::{ClientConfig, Connection, Endpoint, RecvStream, SendStream};

use dpop_bearer::Bearer;

const SOON: Duration = Duration::from_secs(10);

struct TestNode {
    node: Arc<TenzroNode>,
    url: String,
    tx: broadcast::Sender<()>,
    handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
    _tmp: tempfile::TempDir,
    client: reqwest::Client,
}

impl TestNode {
    async fn start() -> Self {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cfg = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            iroh: tenzro_iroh::TenzroIrohConfig::loopback(),
            app_transport: Some(AppTransportConfig {
                listen: "127.0.0.1:0".to_string(),
                url: "https://127.0.0.1/app".to_string(),
                cert: None,
                key: None,
                max_sessions: 8,
                pending_per_ip: 4,
                bytes_per_second: 1 << 30,
                burst_bytes: 1 << 30,
                opens_per_minute: 100,
                pending_per_device: 4,
                sessions_per_identity: 4,
                streams_per_identity: 16,
                idle_secs: 60,
                peer_streams: None,
                paid_mebibytes: None,
                relay_connections_per_identity: None,
            }),
            ..Default::default()
        };
        let mut node = TenzroNode::new(cfg).await.expect("node creation");
        node.start().await.expect("node start");
        let node = Arc::new(node);
        node.bind_self();
        let (tx, rx) = broadcast::channel::<()>(1);
        let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
        let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string());
        let handle =
            tokio::spawn(async move { rpc.start_with_shutdown_and_addr(rx, addr_tx).await });
        let addr = addr_rx.await.expect("bound address");
        Self {
            node,
            url: format!("http://{addr}"),
            tx,
            handle,
            _tmp: tmp,
            client: reqwest::Client::new(),
        }
    }

    async fn onboard(&self, name: &str) -> Bearer {
        Bearer::onboard(&self.client, &self.url, name).await
    }

    /// Connects to the app transport, pinning the certificate it serves,
    /// and reads the challenge.
    async fn connect(&self) -> Session {
        let listener = self.node.app_transport().expect("app transport runs");
        let mut hash = [0u8; 32];
        let served = &listener.pinned_hashes().expect("pinned certificate")[0];
        hex::decode_to_slice(&served.sha256, &mut hash).unwrap();
        let config = ClientConfig::builder()
            .with_bind_default()
            .with_server_certificate_hashes([Sha256Digest::new(hash)])
            .build();
        let endpoint = Endpoint::client(config).unwrap();
        let url = format!("https://127.0.0.1:{}/app", listener.local_addr().port());
        let connection = endpoint.connect(url).await.expect("connect");
        let (send, mut recv) = timeout(SOON, connection.accept_bi())
            .await
            .unwrap()
            .unwrap();
        let Frame::Challenge { nonce } = read_frame(&mut recv).await.unwrap() else {
            panic!("a session starts with a challenge");
        };
        Session {
            _endpoint: endpoint,
            connection,
            control: (send, recv),
            nonce,
        }
    }

    async fn stop(self) {
        let _ = self.tx.send(());
        let _ = timeout(Duration::from_secs(5), self.handle).await;
    }
}

/// A device's end of a session.
struct Session {
    _endpoint: Endpoint<Client>,
    connection: Connection,
    control: (SendStream, RecvStream),
    nonce: String,
}

impl Session {
    async fn say(&mut self, frame: Frame) -> Option<Frame> {
        write_frame(&mut self.control.0, &frame).await.ok()?;
        timeout(SOON, read_frame(&mut self.control.1))
            .await
            .ok()?
            .ok()
    }

    /// The hello `who` makes for the session whose nonce is `nonce`.
    fn hello_for(who: &Bearer, nonce: &str) -> Frame {
        Frame::Hello {
            access_token: who.token.clone(),
            dpop: who
                .holder
                .sign_proof("POST", &sign_in_htu(nonce), Some(&who.token)),
            payment: None,
            binding: None,
        }
    }

    /// Signs in as `who` and returns the identity the node took it for.
    async fn sign_in(&mut self, who: &Bearer) -> String {
        let hello = Self::hello_for(who, &self.nonce);
        match self.say(hello).await {
            Some(Frame::Welcome { did, .. }) => did,
            other => panic!("not welcomed: {other:?}"),
        }
    }
}

#[tokio::test]
#[ignore = "needs this machine's identity key in hardware (TPM 2.0 or Secure Enclave)"]
async fn two_signed_in_devices_exchange_a_stream_through_the_node() {
    let node = TestNode::start().await;
    let alice = node.onboard("alice").await;
    let bob = node.onboard("bob").await;
    let mut a = node.connect().await;
    let mut b = node.connect().await;
    let a_did = a.sign_in(&alice).await;
    let b_did = b.sign_in(&bob).await;
    assert_ne!(a_did, b_did);

    let listening = b
        .say(Frame::Listen {
            from: vec![a_did.clone()],
            apps: Vec::new(),
        })
        .await;
    assert_eq!(listening, Some(Frame::Listening));

    let up: Vec<u8> = (0..150_000u32).map(|i| i as u8).collect();
    let down: Vec<u8> = (0..40_000u32).map(|i| (i * 5) as u8).collect();
    let at_b = async {
        let (mut send, mut recv) = timeout(SOON, b.connection.accept_bi())
            .await
            .unwrap()
            .unwrap();
        let incoming = read_frame(&mut recv).await.unwrap();
        assert!(
            matches!(&incoming, Frame::Incoming { from, app, via: None, .. }
                if from == &a_did && app == "messenger"),
            "{incoming:?}"
        );
        write_frame(&mut send, &Frame::Accept).await.unwrap();
        let mut heard = Vec::new();
        recv.read_to_end(&mut heard).await.unwrap();
        send.write_all(&down).await.unwrap();
        send.shutdown().await.unwrap();
        heard
    };
    let at_a = async {
        let (mut send, mut recv) = a.connection.open_bi().await.unwrap().await.unwrap();
        let open = Frame::Open {
            to: b_did.clone(),
            device: None,
            via: None,
            app: "messenger".to_string(),
        };
        write_frame(&mut send, &open).await.unwrap();
        let opened = timeout(SOON, read_frame(&mut recv)).await.unwrap().unwrap();
        assert!(matches!(opened, Frame::Opened { .. }), "{opened:?}");
        send.write_all(&up).await.unwrap();
        send.shutdown().await.unwrap();
        let mut heard = Vec::new();
        recv.read_to_end(&mut heard).await.unwrap();
        heard
    };
    let (heard_at_b, heard_at_a) =
        timeout(Duration::from_secs(60), async { tokio::join!(at_b, at_a) })
            .await
            .unwrap();
    assert_eq!(heard_at_b, up);
    assert_eq!(heard_at_a, down);

    let meter = node.node.app_transport().unwrap().meter().clone();
    assert_eq!(
        meter.usage(&a_did),
        Usage {
            streams: 1,
            bytes_sent: up.len() as u64,
            bytes_received: down.len() as u64,
        }
    );
    assert_eq!(meter.usage(&b_did), Usage::default());
    node.stop().await;
}

#[tokio::test]
#[ignore = "needs this machine's identity key in hardware (TPM 2.0 or Secure Enclave)"]
async fn a_device_without_a_token_of_this_node_or_its_key_is_refused() {
    let node = TestNode::start().await;
    let alice = node.onboard("alice").await;
    let mallory = dpop_bearer::DpopHolder::new();

    // No token at all.
    let mut nobody = node.connect().await;
    let answer = nobody
        .say(Frame::Hello {
            access_token: String::new(),
            dpop: String::new(),
            payment: None,
            binding: None,
        })
        .await;
    assert!(matches!(answer, Some(Frame::Refused { .. })), "{answer:?}");

    // Alice's token with a proof by a key the token is not bound to.
    let mut thief = node.connect().await;
    let answer = thief
        .say(Frame::Hello {
            access_token: alice.token.clone(),
            dpop: mallory.sign_proof("POST", &sign_in_htu(&thief.nonce), Some(&alice.token)),
            payment: None,
            binding: None,
        })
        .await;
    assert!(matches!(answer, Some(Frame::Refused { .. })), "{answer:?}");
    timeout(SOON, thief.connection.closed()).await.unwrap();
    node.stop().await;
}

#[tokio::test]
#[ignore = "needs this machine's identity key in hardware (TPM 2.0 or Secure Enclave)"]
async fn a_proof_made_for_one_session_does_not_sign_in_to_another() {
    let node = TestNode::start().await;
    let alice = node.onboard("alice").await;
    let mut first = node.connect().await;
    let mut second = node.connect().await;

    // A hello made for the first session, presented on the second before
    // the first used it: the nonce it was made over is not the second's.
    let hello = Session::hello_for(&alice, &first.nonce);
    let answer = second.say(hello.clone()).await;
    assert!(matches!(answer, Some(Frame::Refused { .. })), "{answer:?}");

    // On its own session it signs in, once.
    let answer = first.say(hello.clone()).await;
    assert!(matches!(answer, Some(Frame::Welcome { .. })), "{answer:?}");
    let again = first.say(hello).await;
    assert_eq!(again, None, "a used proof does not renew the session");
    timeout(SOON, first.connection.closed()).await.unwrap();
    node.stop().await;
}

#[tokio::test]
#[ignore = "needs this machine's identity key in hardware (TPM 2.0 or Secure Enclave)"]
async fn the_node_signs_its_welcome_and_says_where_devices_reach_it() {
    let node = TestNode::start().await;
    let alice = node.onboard("alice").await;
    let mut a = node.connect().await;
    let hello = Session::hello_for(&alice, &a.nonce);
    let Some(Frame::Welcome {
        did,
        device,
        expires_at,
        signature,
        pq_signature,
    }) = a.say(hello).await
    else {
        panic!("not welcomed");
    };

    // Signed by the key the node's access tokens verify under, and by the
    // ML-DSA-65 key of its machine identity, over this session's nonce.
    let digest = welcome_digest(&a.nonce, &did, &device, expires_at);
    let mut sec1 = vec![4u8];
    sec1.extend(node.node.auth_engine().unwrap().signer().public_key());
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    let signature = URL_SAFE_NO_PAD.decode(signature).unwrap();
    key.verify_prehash(
        &digest,
        &p256::ecdsa::Signature::from_slice(&signature).unwrap(),
    )
    .expect("P-256 signature");
    let machine_pq = tenzro_node::identity_bootstrap::machine_ml_dsa_public().unwrap();
    let pq_signature = URL_SAFE_NO_PAD.decode(pq_signature).unwrap();
    ml_dsa_verify(&machine_pq, WELCOME_PQ_CONTEXT, &digest, &pq_signature)
        .expect("ML-DSA-65 signature");

    let served: Vec<String> = node
        .node
        .app_transport()
        .unwrap()
        .pinned_hashes()
        .unwrap()
        .into_iter()
        .map(|h| h.sha256)
        .collect();
    let call = |method: &'static str| alice.call(&node.client, &node.url, method, json!({}));

    let info = call("tenzro_getAppTransportInfo").await;
    let info = &info["result"];
    assert_eq!(info["url"], "https://127.0.0.1/app", "{info}");
    assert_eq!(info["publication"]["listener"], "app-transport");
    let published: Vec<&str> = info["publication"]["hashes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["sha256"].as_str().unwrap())
        .collect();
    assert_eq!(published, served);

    let usage = call("tenzro_getAppTransportUsage").await;
    assert_eq!(usage["result"]["did"], did.as_str(), "{usage}");
    assert_eq!(usage["result"]["usage"]["streams"], 0);

    let document = call("tenzro_nodeDidDocument").await;
    let services = document["result"]["service"].as_array().unwrap();
    let of_type =
        |kind: &str| -> Vec<&Value> { services.iter().filter(|s| s["type"] == kind).collect() };
    assert_eq!(
        of_type("TenzroAppTransport")[0]["serviceEndpoint"],
        "https://127.0.0.1/app"
    );
    let pinned: Vec<&str> = of_type("TenzroPinnedCertSha256")
        .iter()
        .map(|s| s["serviceEndpoint"].as_str().unwrap())
        .collect();
    assert_eq!(pinned, served);
    node.stop().await;
}
