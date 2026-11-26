use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use tenzro_crypto::pq::{MlDsaSigningKey, ml_dsa_verify};
use tenzro_iroh::app_stream::{
    EXPORTER_BYTES, EXPORTER_LABEL, Frame, Usage, WELCOME_PQ_CONTEXT, decode_datagram,
    encode_datagram, read_frame, sign_in_htu, sign_in_htu_bound, welcome_digest, write_frame,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use wtransport::endpoint::endpoint_side::Client;
use wtransport::tls::Sha256Digest;
use wtransport::{ClientConfig, Connection, Endpoint, RecvStream, SendStream};

use super::*;

const A: &str = "did:tenzro:human:a";
const B: &str = "did:tenzro:human:b";
const SOON: Duration = Duration::from_secs(5);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Takes a token of the form `did|device|expires_at` whose proof is the URI
/// it must name; one starting `paid:` names a caller the policy asks to
/// pay [`PRICE`] a mebibyte.
struct TokenIsItsClaims;

/// The stand-in policy's price of a mebibyte.
const PRICE: &str = "3";

impl SignIn for TokenIsItsClaims {
    fn admit(&self, htu: &str, access_token: &str, dpop: &str) -> Result<Admitted, Refusal> {
        if dpop != htu {
            return Err(Refusal::No(
                "the proof was not made for this session".to_string(),
            ));
        }
        let (paid, claims) = match access_token.strip_prefix("paid:") {
            Some(claims) => (true, claims),
            None => (false, access_token),
        };
        let mut parts = claims.split('|');
        let admitted = match (parts.next(), parts.next(), parts.next().map(str::parse)) {
            (Some(did), Some(device), Some(Ok(expires_at))) if !did.is_empty() => Admitted {
                did: did.to_string(),
                device: device.to_string(),
                expires_at,
            },
            _ => {
                return Err(Refusal::No(
                    "sign in with an access token of this node".to_string(),
                ));
            }
        };
        if paid {
            return Err(Refusal::Pay {
                admitted,
                price: PRICE.to_string(),
                asset: "TNZO".to_string(),
            });
        }
        Ok(admitted)
    }

    fn vouch(&self, digest: &[u8; 32]) -> Result<Vouch, String> {
        let signature: p256::ecdsa::Signature = node_p256()
            .sign_prehash(digest)
            .map_err(|e| e.to_string())?;
        Ok(Vouch {
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            pq_signature: URL_SAFE_NO_PAD.encode(node_ml_dsa().sign(WELCOME_PQ_CONTEXT, digest)),
        })
    }
}

/// The stand-in node's access-token key.
fn node_p256() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap()
}

/// The stand-in node's ML-DSA-65 key.
fn node_ml_dsa() -> &'static MlDsaSigningKey {
    static KEY: OnceLock<MlDsaSigningKey> = OnceLock::new();
    KEY.get_or_init(|| MlDsaSigningKey::from_seed(&[9u8; 32]).unwrap())
}

/// Whether `welcome` carries both of the node's signatures over `nonce` and
/// what it says.
fn vouched(welcome: &Frame, nonce: &str) -> bool {
    let Frame::Welcome {
        did,
        device,
        expires_at,
        signature,
        pq_signature,
    } = welcome
    else {
        return false;
    };
    let digest = welcome_digest(nonce, did, device, *expires_at);
    let classical = URL_SAFE_NO_PAD
        .decode(signature)
        .ok()
        .and_then(|bytes| p256::ecdsa::Signature::from_slice(&bytes).ok())
        .is_some_and(|sig| {
            node_p256()
                .verifying_key()
                .verify_prehash(&digest, &sig)
                .is_ok()
        });
    let pq = URL_SAFE_NO_PAD.decode(pq_signature).is_ok_and(|sig| {
        ml_dsa_verify(
            node_ml_dsa().verifying_key_bytes(),
            WELCOME_PQ_CONTEXT,
            &digest,
            &sig,
        )
        .is_ok()
    });
    classical && pq
}

fn config() -> AppTransportConfig {
    AppTransportConfig {
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
    }
}

/// Reaches no other node.
struct NoPeers;

#[async_trait]
impl Peers for NoPeers {
    async fn dial(&self, did: &str) -> Result<Pipe, String> {
        Err(format!("{did} is not a node this one knows"))
    }
}

/// The node streams between nodes come from in these tests.
const X_NODE: &str = "did:tenzro:machine:x";
/// The node they reach.
const Y_NODE: &str = "did:tenzro:machine:y";

/// Reaches [`Y_NODE`], the listener it comes to hold, over an in-memory pipe,
/// as [`X_NODE`].
#[derive(Default)]
struct ReachesY(Arc<OnceLock<Arc<AppTransport>>>);

#[async_trait]
impl Peers for ReachesY {
    async fn dial(&self, did: &str) -> Result<Pipe, String> {
        let y = self
            .0
            .get()
            .filter(|_| did == Y_NODE)
            .ok_or_else(|| format!("{did} is not a node this one knows"))?
            .clone();
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        let (their_recv, their_send) = tokio::io::split(theirs);
        tokio::spawn(async move {
            y.serve_peer(
                X_NODE.to_string(),
                (Box::new(their_recv), Box::new(their_send)),
            )
            .await;
        });
        let (recv, send) = tokio::io::split(ours);
        Ok((Box::new(recv), Box::new(send)))
    }
}

/// The credential the stand-in ledger takes.
const PAID: &str = "paid-credential";

/// Takes [`PAID`] as payment for `budget` bytes and records what it settles.
struct Ledger {
    budget: u64,
    settled: parking_lot::Mutex<Vec<(String, u64)>>,
    on_settle: tokio::sync::Notify,
}

impl Ledger {
    fn new(budget: u64) -> Arc<Self> {
        Arc::new(Self {
            budget,
            settled: parking_lot::Mutex::new(Vec::new()),
            on_settle: tokio::sync::Notify::new(),
        })
    }

    /// The settlements, once there are `n`.
    async fn settled(&self, n: usize) -> Vec<(String, u64)> {
        timeout(SOON, async {
            loop {
                let notified = self.on_settle.notified();
                if self.settled.lock().len() >= n {
                    return self.settled.lock().clone();
                }
                notified.await;
            }
        })
        .await
        .expect("settled in time")
    }
}

#[async_trait]
impl Payments for Ledger {
    async fn quote(&self, price: &str, asset: &str) -> Result<String, String> {
        Ok(format!("{{\"price\":\"{price}\",\"asset\":\"{asset}\"}}"))
    }

    async fn hold(&self, credential: &str, price: &str, _asset: &str) -> Result<Hold, String> {
        if credential != PAID {
            return Err("payment refused".to_string());
        }
        Ok(Hold {
            credential: credential.to_string(),
            price: price.parse().unwrap(),
            bytes: self.budget,
        })
    }

    async fn settle(&self, hold: Hold, mebibytes: u64) {
        self.settled.lock().push((hold.credential, mebibytes));
        self.on_settle.notify_waiters();
    }
}

fn start(config: &AppTransportConfig) -> Result<AppTransport, String> {
    AppTransport::start(
        config,
        Arc::new(TokenIsItsClaims),
        Arc::new(NoPeers),
        Ledger::new(0),
    )
}

fn listener() -> AppTransport {
    start(&config()).unwrap()
}

fn pin(hash: [u8; 32]) -> Endpoint<Client> {
    let config = ClientConfig::builder()
        .with_bind_default()
        .with_server_certificate_hashes([Sha256Digest::new(hash)])
        .build();
    Endpoint::client(config).unwrap()
}

fn served_hash(listener: &AppTransport) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hex::decode_to_slice(&listener.pinned_hashes().unwrap()[0].sha256, &mut hash).unwrap();
    hash
}

fn url(listener: &AppTransport) -> String {
    format!("https://127.0.0.1:{}/app", listener.local_addr().port())
}

/// A device's end of a session.
struct Device {
    _endpoint: Endpoint<Client>,
    connection: Connection,
    control: (SendStream, RecvStream),
    nonce: String,
}

impl Device {
    /// Ends the control stream, which the connection resends until the node
    /// has it, and waits for the node to end the session and close the
    /// connection. A close sent from here is sent once and may not arrive.
    async fn end(mut self) {
        self.control.0.shutdown().await.unwrap();
        timeout(SOON, self.connection.closed())
            .await
            .expect("the node ended the session");
    }

    /// Connects and reads the challenge.
    async fn connect(listener: &AppTransport) -> Self {
        let endpoint = pin(served_hash(listener));
        let connection = endpoint.connect(url(listener)).await.unwrap();
        let (send, mut recv) = timeout(SOON, connection.accept_bi())
            .await
            .unwrap()
            .unwrap();
        let Frame::Challenge { nonce } = read_frame(&mut recv).await.unwrap() else {
            panic!("a session starts with a challenge");
        };
        Self {
            _endpoint: endpoint,
            connection,
            control: (send, recv),
            nonce,
        }
    }

    async fn say(&mut self, frame: Frame) -> Option<Frame> {
        write_frame(&mut self.control.0, &frame).await.ok()?;
        timeout(SOON, read_frame(&mut self.control.1))
            .await
            .ok()?
            .ok()
    }

    async fn hello(&mut self, token: String) -> Option<Frame> {
        self.hello_paying(token, None).await
    }

    async fn hello_paying(&mut self, token: String, payment: Option<&str>) -> Option<Frame> {
        let dpop = sign_in_htu(&self.nonce);
        self.say(Frame::Hello {
            access_token: token,
            dpop,
            payment: payment.map(str::to_string),
            binding: None,
        })
        .await
    }

    /// The keying material this end exports from the session's TLS secrets.
    fn binding(&self) -> String {
        let mut out = [0u8; EXPORTER_BYTES];
        self.connection
            .export_keying_material(&mut out, EXPORTER_LABEL, self.nonce.as_bytes())
            .unwrap();
        hex::encode(out)
    }

    /// Connects and signs in as `device` of `did` for a minute.
    async fn sign_in(listener: &AppTransport, did: &str, device: &str) -> Self {
        let mut this = Self::connect(listener).await;
        let answer = this.hello(format!("{did}|{device}|{}", now() + 60)).await;
        let welcome = answer.expect("welcomed");
        assert!(vouched(&welcome, &this.nonce), "{welcome:?}");
        this
    }

    async fn listen(&mut self, from: &[&str], apps: &[&str]) {
        let own = |list: &[&str]| list.iter().map(|s| s.to_string()).collect();
        let answer = self
            .say(Frame::Listen {
                from: own(from),
                apps: own(apps),
            })
            .await;
        assert_eq!(answer, Some(Frame::Listening));
    }

    /// Opens a stream to `to` and reads the node's answer.
    async fn open(&self, to: &str, app: &str) -> (SendStream, RecvStream, Frame) {
        self.open_via(to, None, app).await
    }

    /// Opens a stream to `to`, signed in to the node `via` when given.
    async fn open_via(
        &self,
        to: &str,
        via: Option<&str>,
        app: &str,
    ) -> (SendStream, RecvStream, Frame) {
        let (mut send, mut recv) = self.connection.open_bi().await.unwrap().await.unwrap();
        let open = Frame::Open {
            to: to.to_string(),
            device: None,
            via: via.map(str::to_string),
            app: app.to_string(),
        };
        write_frame(&mut send, &open).await.unwrap();
        let answer = timeout(SOON, read_frame(&mut recv)).await.unwrap().unwrap();
        (send, recv, answer)
    }

    /// The next stream offered to this device, if one comes soon.
    async fn offered(&self, within: Duration) -> Option<(SendStream, RecvStream, Frame)> {
        let (send, mut recv) = timeout(within, self.connection.accept_bi())
            .await
            .ok()?
            .ok()?;
        let frame = timeout(SOON, read_frame(&mut recv)).await.ok()?.ok()?;
        Some((send, recv, frame))
    }
}

#[tokio::test]
async fn a_device_that_does_not_sign_in_is_refused_and_cut_off() {
    let listener = listener();

    let mut no_token = Device::connect(&listener).await;
    let answer = no_token.hello(String::new()).await;
    assert!(matches!(answer, Some(Frame::Refused { .. })), "{answer:?}");
    timeout(SOON, no_token.connection.closed()).await.unwrap();

    // Anything but a hello first ends the session unanswered.
    let mut impatient = Device::connect(&listener).await;
    let answer = impatient
        .say(Frame::Listen {
            from: vec![A.to_string()],
            apps: Vec::new(),
        })
        .await;
    assert_eq!(answer, None);
    timeout(SOON, impatient.connection.closed()).await.unwrap();
    assert_eq!(listener.meter().all(), Vec::new());
}

#[tokio::test]
async fn an_address_holds_only_so_many_connections_before_they_sign_in() {
    let config = AppTransportConfig {
        pending_per_ip: 2,
        ..config()
    };
    let listener = start(&config).unwrap();
    let mut first = Device::connect(&listener).await;
    let _second = Device::connect(&listener).await;

    let third = pin(served_hash(&listener));
    let refused = timeout(SOON, third.connect(url(&listener))).await.unwrap();
    assert!(refused.is_err(), "the third unsigned connection is refused");

    // Another address is not held to this one's count.
    #[cfg(target_os = "linux")]
    {
        let elsewhere = ClientConfig::builder()
            .with_bind_address("127.0.0.2:0".parse().unwrap())
            .with_server_certificate_hashes([Sha256Digest::new(served_hash(&listener))])
            .build();
        let elsewhere = Endpoint::client(elsewhere).unwrap();
        assert!(elsewhere.connect(url(&listener)).await.is_ok());
    }

    // A device that signs in stops counting, and is served as before.
    let answer = first.hello(format!("{A}|phone|{}", now() + 60)).await;
    assert!(matches!(answer, Some(Frame::Welcome { .. })), "{answer:?}");
    let _fourth = Device::connect(&listener).await;
    first.listen(&[B], &[]).await;
}

#[tokio::test]
async fn a_hello_bound_to_the_tls_session_signs_in_and_a_foreign_binding_does_not() {
    let listener = listener();
    let mut device = Device::connect(&listener).await;
    let binding = device.binding();
    let token = format!("{A}|phone|{}", now() + 60);
    let foreign = device
        .say(Frame::Hello {
            access_token: token.clone(),
            dpop: sign_in_htu_bound(&device.nonce, &"00".repeat(EXPORTER_BYTES)),
            payment: None,
            binding: Some("00".repeat(EXPORTER_BYTES)),
        })
        .await;
    assert!(
        matches!(&foreign, Some(Frame::Refused { reason }) if reason.contains("not this session")),
        "{foreign:?}"
    );

    let mut device = Device::connect(&listener).await;
    let binding_now = device.binding();
    assert_ne!(binding, binding_now, "each session exports its own");
    let bound = device
        .say(Frame::Hello {
            access_token: token,
            dpop: sign_in_htu_bound(&device.nonce, &binding_now),
            payment: None,
            binding: Some(binding_now),
        })
        .await;
    assert!(matches!(bound, Some(Frame::Welcome { .. })), "{bound:?}");
}

#[tokio::test]
async fn a_hello_made_for_one_session_is_refused_on_another() {
    let listener = listener();
    let first = Device::connect(&listener).await;
    let mut second = Device::connect(&listener).await;
    assert_ne!(first.nonce, second.nonce);
    let answer = second
        .say(Frame::Hello {
            access_token: format!("{A}|phone|{}", now() + 60),
            dpop: sign_in_htu(&first.nonce),
            payment: None,
            binding: None,
        })
        .await;
    assert!(matches!(answer, Some(Frame::Refused { .. })), "{answer:?}");
}

#[tokio::test]
async fn two_devices_exchange_a_stream_and_every_byte_is_counted_for_the_opener() {
    let listener = listener();
    let a = Device::sign_in(&listener, A, "phone").await;
    let mut b = Device::sign_in(&listener, B, "laptop").await;
    b.listen(&[A], &[]).await;

    let up: Vec<u8> = (0..300_000u32).map(|i| i as u8).collect();
    let down: Vec<u8> = (0..90_000u32).map(|i| (i * 3) as u8).collect();

    let at_b = async {
        let (mut send, mut recv, frame) = b.offered(SOON).await.unwrap();
        assert_eq!(
            frame,
            Frame::Incoming {
                from: A.to_string(),
                device: "phone".to_string(),
                via: None,
                app: "messenger".to_string(),
                flow: Some(1),
            }
        );
        write_frame(&mut send, &Frame::Accept).await.unwrap();
        let mut heard = Vec::new();
        recv.read_to_end(&mut heard).await.unwrap();
        send.write_all(&down).await.unwrap();
        send.shutdown().await.unwrap();
        heard
    };
    let at_a = async {
        let (mut send, mut recv, answer) = a.open(B, "messenger").await;
        assert_eq!(
            answer,
            Frame::Opened {
                device: "laptop".to_string(),
                flow: Some(1),
            }
        );
        send.write_all(&up).await.unwrap();
        send.shutdown().await.unwrap();
        let mut heard = Vec::new();
        recv.read_to_end(&mut heard).await.unwrap();
        heard
    };
    let (heard_at_b, heard_at_a) =
        timeout(Duration::from_secs(30), async { tokio::join!(at_b, at_a) })
            .await
            .unwrap();
    assert_eq!(heard_at_b, up);
    assert_eq!(heard_at_a, down);
    assert_eq!(
        listener.meter().usage(A),
        Usage {
            streams: 1,
            bytes_sent: up.len() as u64,
            bytes_received: down.len() as u64,
        }
    );
    assert_eq!(listener.meter().usage(B), Usage::default());
}

#[tokio::test]
async fn datagrams_flow_between_the_ends_of_an_accepted_stream_while_it_lasts() {
    let listener = listener();
    let a = Device::sign_in(&listener, A, "phone").await;
    let mut b = Device::sign_in(&listener, B, "laptop").await;
    b.listen(&[A], &[]).await;

    let taking = async {
        let (mut send, recv, frame) = b.offered(SOON).await.unwrap();
        let Frame::Incoming {
            flow: Some(flow), ..
        } = frame
        else {
            panic!("{frame:?}");
        };
        write_frame(&mut send, &Frame::Accept).await.unwrap();
        (send, recv, flow)
    };
    let ((b_send, b_recv, b_flow), (a_send, a_recv, opened)) =
        tokio::join!(taking, a.open(B, "call"));
    let Frame::Opened {
        flow: Some(a_flow), ..
    } = opened
    else {
        panic!("{opened:?}");
    };

    // A to B, under B's number for the flow; and back.
    a.connection
        .send_datagram(encode_datagram(a_flow, b"hello"))
        .unwrap();
    let got = timeout(SOON, b.connection.receive_datagram())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        decode_datagram(&got.payload()),
        Some((b_flow, &b"hello"[..]))
    );
    b.connection
        .send_datagram(encode_datagram(b_flow, b"hi"))
        .unwrap();
    let got = timeout(SOON, a.connection.receive_datagram())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(decode_datagram(&got.payload()), Some((a_flow, &b"hi"[..])));
    // Both ways count against the opener.
    let usage = listener.meter().usage(A);
    assert_eq!((usage.bytes_sent, usage.bytes_received), (5, 2));

    // Once the stream ends, the flow goes with it.
    drop((a_send, a_recv, b_send, b_recv));
    tokio::time::sleep(Duration::from_millis(300)).await;
    a.connection
        .send_datagram(encode_datagram(a_flow, b"late"))
        .unwrap();
    assert!(
        timeout(Duration::from_millis(300), b.connection.receive_datagram())
            .await
            .is_err(),
        "a datagram after the stream ended is dropped"
    );
}

#[tokio::test]
async fn a_sender_the_target_did_not_name_never_reaches_it() {
    let listener = listener();
    let a = Device::sign_in(&listener, A, "phone").await;
    let mut b = Device::sign_in(&listener, B, "laptop").await;

    // Before B says who may reach it, and after it names somebody else.
    let (_, _, before) = a.open(B, "messenger").await;
    b.listen(&["did:tenzro:human:c"], &["files"]).await;
    let (_, _, unlisted) = a.open(B, "messenger").await;
    let (_, _, absent) = a.open("did:tenzro:human:nobody", "messenger").await;
    assert!(matches!(before, Frame::Refused { .. }), "{before:?}");
    assert_eq!(before, unlisted);
    assert_eq!(
        unlisted, absent,
        "an unlisted sender cannot tell the target is here"
    );
    assert!(b.offered(Duration::from_millis(500)).await.is_none());
    assert_eq!(listener.meter().usage(A), Usage::default());

    // The label B listens for lets A through.
    let (reached, opened) = tokio::join!(
        async {
            let (mut send, _recv, frame) = b.offered(SOON).await.unwrap();
            write_frame(&mut send, &Frame::Accept).await.unwrap();
            frame
        },
        a.open(B, "files")
    );
    assert!(matches!(reached, Frame::Incoming { .. }), "{reached:?}");
    assert!(matches!(opened.2, Frame::Opened { .. }), "{:?}", opened.2);
}

#[tokio::test]
async fn a_declined_stream_is_refused_to_its_opener_and_not_counted() {
    let listener = listener();
    let a = Device::sign_in(&listener, A, "phone").await;
    let mut b = Device::sign_in(&listener, B, "laptop").await;
    b.listen(&[A], &[]).await;
    let (answer, ()) = tokio::join!(a.open(B, "messenger"), async {
        let (mut send, _recv, _) = b.offered(SOON).await.unwrap();
        write_frame(&mut send, &Frame::Decline).await.unwrap();
    });
    assert!(matches!(answer.2, Frame::Refused { .. }), "{:?}", answer.2);
    assert_eq!(listener.meter().usage(A), Usage::default());
}

#[tokio::test]
async fn a_node_that_carries_no_streams_between_nodes_refuses_an_open_via_another() {
    let listener = listener();
    let a = Device::sign_in(&listener, A, "phone").await;
    let (_, _, answer) = a.open_via(B, Some(Y_NODE), "messenger").await;
    assert!(matches!(answer, Frame::Refused { .. }), "{answer:?}");
}

/// A listener that carries streams between nodes: [`X_NODE`] reaching
/// [`Y_NODE`] when `reaches` is given, [`Y_NODE`] otherwise.
fn between(peer_streams: u32, reaches: Option<ReachesY>) -> AppTransport {
    let config = AppTransportConfig {
        peer_streams: Some(peer_streams),
        ..config()
    };
    let peers: Arc<dyn Peers> = match reaches {
        Some(reaches) => Arc::new(reaches),
        None => Arc::new(NoPeers),
    };
    AppTransport::start(&config, Arc::new(TokenIsItsClaims), peers, Ledger::new(0)).unwrap()
}

#[tokio::test]
async fn a_stream_reaches_a_device_on_another_node_and_each_node_counts_its_side() {
    let reaches = ReachesY::default();
    let to_y = reaches.0.clone();
    let x = between(4, Some(reaches));
    let y = Arc::new(between(4, None));
    let _ = to_y.set(y.clone());

    let a = Device::sign_in(&x, A, "phone").await;
    let mut b = Device::sign_in(&y, B, "laptop").await;
    b.listen(&[A], &[]).await;

    let up: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
    let down: Vec<u8> = (0..70_000u32).map(|i| (i * 7) as u8).collect();
    let at_b = async {
        let (mut send, mut recv, frame) = b.offered(SOON).await.unwrap();
        assert_eq!(
            frame,
            Frame::Incoming {
                from: A.to_string(),
                device: "phone".to_string(),
                via: Some(X_NODE.to_string()),
                app: "messenger".to_string(),
                flow: None,
            }
        );
        write_frame(&mut send, &Frame::Accept).await.unwrap();
        let mut heard = Vec::new();
        recv.read_to_end(&mut heard).await.unwrap();
        send.write_all(&down).await.unwrap();
        send.shutdown().await.unwrap();
        heard
    };
    let at_a = async {
        let (mut send, mut recv, answer) = a.open_via(B, Some(Y_NODE), "messenger").await;
        assert_eq!(
            answer,
            Frame::Opened {
                device: "laptop".to_string(),
                flow: None,
            }
        );
        send.write_all(&up).await.unwrap();
        send.shutdown().await.unwrap();
        let mut heard = Vec::new();
        recv.read_to_end(&mut heard).await.unwrap();
        heard
    };
    let (heard_at_b, heard_at_a) =
        timeout(Duration::from_secs(30), async { tokio::join!(at_b, at_a) })
            .await
            .unwrap();
    assert_eq!(heard_at_b, up);
    assert_eq!(heard_at_a, down);
    let carried = Usage {
        streams: 1,
        bytes_sent: up.len() as u64,
        bytes_received: down.len() as u64,
    };
    // The opener's node counts the opener; the target's node counts the node
    // that carried the stream there.
    assert_eq!(x.meter().usage(A), carried);
    assert_eq!(y.meter().usage(X_NODE), carried);
    assert_eq!(y.meter().usage(A), Usage::default());
}

#[tokio::test]
async fn an_open_via_another_node_the_target_did_not_name_is_refused_like_any_other() {
    let reaches = ReachesY::default();
    let to_y = reaches.0.clone();
    let x = between(4, Some(reaches));
    let y = Arc::new(between(4, None));
    let _ = to_y.set(y.clone());

    let a = Device::sign_in(&x, A, "phone").await;
    let mut b = Device::sign_in(&y, B, "laptop").await;
    b.listen(&["did:tenzro:human:c"], &[]).await;
    let (_, _, answer) = a.open_via(B, Some(Y_NODE), "messenger").await;
    let (_, _, absent) = a
        .open_via("did:tenzro:human:nobody", Some(Y_NODE), "messenger")
        .await;
    assert!(matches!(answer, Frame::Refused { .. }), "{answer:?}");
    assert_eq!(answer, absent, "an unlisted sender learns nothing");
    assert!(b.offered(Duration::from_millis(300)).await.is_none());
    assert_eq!(y.meter().usage(X_NODE), Usage::default());
}

#[tokio::test]
async fn a_node_carries_only_so_many_streams_from_one_other_node() {
    let y = Arc::new(between(1, None));
    // The first stream from X holds its place while it waits for its head.
    let (_first, theirs) = tokio::io::duplex(1024);
    let (recv, send) = tokio::io::split(theirs);
    let held = y.clone();
    tokio::spawn(async move {
        held.serve_peer(X_NODE.to_string(), (Box::new(recv), Box::new(send)))
            .await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (mut second, theirs) = tokio::io::duplex(1024);
    let (recv, send) = tokio::io::split(theirs);
    let serving = y.clone();
    tokio::spawn(async move {
        serving
            .serve_peer(X_NODE.to_string(), (Box::new(recv), Box::new(send)))
            .await;
    });
    let answer = timeout(SOON, read_frame(&mut second))
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(&answer, Frame::Refused { reason } if reason.contains("as many streams")),
        "{answer:?}"
    );
}

#[tokio::test]
async fn a_session_ends_with_its_token_unless_a_fresh_hello_arrives() {
    let listener = listener();

    let mut lapsing = Device::connect(&listener).await;
    let answer = lapsing.hello(format!("{A}|phone|{}", now() + 2)).await;
    assert!(matches!(answer, Some(Frame::Welcome { .. })), "{answer:?}");
    timeout(SOON, lapsing.connection.closed()).await.unwrap();

    let mut renewing = Device::connect(&listener).await;
    let answer = renewing.hello(format!("{B}|laptop|{}", now() + 2)).await;
    assert!(matches!(answer, Some(Frame::Welcome { .. })), "{answer:?}");
    let later = now() + 60;
    let answer = renewing.hello(format!("{B}|laptop|{later}")).await;
    let renewed = answer.expect("renewed");
    assert!(
        matches!(&renewed, Frame::Welcome { did, device, expires_at, .. }
            if did == B && device == "laptop" && *expires_at == later),
        "{renewed:?}"
    );
    assert!(vouched(&renewed, &renewing.nonce));
    assert!(
        !vouched(&renewed, "another session's nonce"),
        "a welcome is bound to its session"
    );
    tokio::time::sleep(Duration::from_secs(4)).await;
    renewing.listen(&[A], &[]).await;

    // A fresh hello cannot turn the session into another identity's.
    let answer = renewing.hello(format!("{A}|laptop|{later}")).await;
    assert_eq!(answer, None);
    timeout(SOON, renewing.connection.closed()).await.unwrap();
}

#[tokio::test]
async fn a_client_that_pins_another_hash_does_not_connect() {
    let listener = listener();
    let stranger = pin([7u8; 32]);
    assert!(stranger.connect(url(&listener)).await.is_err());
    let holder = pin(served_hash(&listener));
    assert!(holder.connect(url(&listener)).await.is_ok());
}

#[tokio::test]
async fn sessions_are_taken_on_the_configured_path_only() {
    let listener = listener();
    let endpoint = pin(served_hash(&listener));
    let elsewhere = format!("https://127.0.0.1:{}/other", listener.local_addr().port());
    assert!(endpoint.connect(elsewhere).await.is_err());
}

#[tokio::test]
async fn a_listener_needs_an_https_url_and_both_or_neither_of_cert_and_key() {
    let start = |config: AppTransportConfig| start(&config).map(|_| ());
    assert!(
        start(AppTransportConfig {
            url: "http://127.0.0.1/app".to_string(),
            ..config()
        })
        .is_err()
    );
    assert!(
        start(AppTransportConfig {
            cert: Some("/nonexistent/cert.pem".into()),
            ..config()
        })
        .is_err()
    );
    assert!(
        start(AppTransportConfig {
            listen: "not an address".to_string(),
            ..config()
        })
        .is_err()
    );
    assert!(
        start(AppTransportConfig {
            idle_secs: 0,
            ..config()
        })
        .is_err()
    );
    assert!(start(config()).is_ok());
}

#[tokio::test]
async fn an_identity_signs_in_at_most_so_many_devices_at_once() {
    let listener = start(&AppTransportConfig {
        sessions_per_identity: 2,
        ..config()
    })
    .unwrap();
    let _phone = Device::sign_in(&listener, A, "phone").await;
    let _laptop = Device::sign_in(&listener, A, "laptop").await;
    let mut third = Device::connect(&listener).await;
    let answer = third.hello(format!("{A}|tablet|{}", now() + 60)).await;
    assert!(
        matches!(&answer, Some(Frame::Refused { reason }) if reason.contains("as many as one identity may")),
        "{answer:?}"
    );
    // Another identity is not held by this one's devices.
    let _other = Device::sign_in(&listener, B, "tablet").await;
}

#[tokio::test]
async fn an_identity_holds_at_most_so_many_streams_open_at_once() {
    let listener = start(&AppTransportConfig {
        streams_per_identity: 1,
        ..config()
    })
    .unwrap();
    let a = Device::sign_in(&listener, A, "phone").await;
    let mut b = Device::sign_in(&listener, B, "laptop").await;
    b.listen(&[A], &[]).await;
    let taking = async {
        let (mut send, _recv, _) = b.offered(SOON).await.unwrap();
        write_frame(&mut send, &Frame::Accept).await.unwrap();
        send
    };
    let (_held, (_s, _r, first)) = tokio::join!(taking, a.open(B, "messenger"));
    assert!(matches!(first, Frame::Opened { .. }), "{first:?}");
    let (_, _, second) = a.open(B, "messenger").await;
    assert!(
        matches!(&second, Frame::Refused { reason } if reason.contains("as many streams")),
        "{second:?}"
    );
}

const MIB: u64 = 1 << 20;

fn paying(ledger: &Arc<Ledger>) -> AppTransport {
    AppTransport::start(
        &config(),
        Arc::new(TokenIsItsClaims),
        Arc::new(NoPeers),
        ledger.clone(),
    )
    .unwrap()
}

/// Signs in as a caller the policy asks to pay, paying with `credential`.
async fn sign_in_paying(
    listener: &AppTransport,
    did: &str,
    credential: &str,
) -> (Device, Option<Frame>) {
    let mut device = Device::connect(listener).await;
    let token = format!("paid:{did}|phone|{}", now() + 60);
    let required = device.hello(token.clone()).await;
    assert!(
        matches!(&required, Some(Frame::PaymentRequired { price, asset, .. })
            if price == PRICE && asset == "TNZO"),
        "{required:?}"
    );
    let answer = device.hello_paying(token, Some(credential)).await;
    (device, answer)
}

#[tokio::test]
async fn a_device_the_policy_asks_to_pay_is_quoted_then_signs_in_with_its_payment() {
    let ledger = Ledger::new(3 * MIB);
    let listener = paying(&ledger);
    let (device, answer) = sign_in_paying(&listener, A, PAID).await;
    let welcome = answer.expect("welcomed");
    assert!(vouched(&welcome, &device.nonce), "{welcome:?}");

    // A credential the ledger does not take is refused, and so is a second
    // hello without one.
    let (_, refused) = sign_in_paying(&listener, B, "forged").await;
    assert!(
        matches!(refused, Some(Frame::Refused { .. })),
        "{refused:?}"
    );
    let mut stubborn = Device::connect(&listener).await;
    let token = format!("paid:{B}|phone|{}", now() + 60);
    stubborn.hello(token.clone()).await;
    let answer = stubborn.hello(token).await;
    assert!(
        matches!(&answer, Some(Frame::Refused { reason }) if reason.contains("pay")),
        "{answer:?}"
    );
}

#[tokio::test]
async fn a_paid_session_is_charged_by_the_mebibyte_for_what_it_carried_when_it_ends() {
    let ledger = Ledger::new(8 * MIB);
    let listener = paying(&ledger);
    let (a, _) = sign_in_paying(&listener, A, PAID).await;
    let mut b = Device::sign_in(&listener, B, "laptop").await;
    b.listen(&[A], &[]).await;

    let up = vec![1u8; (3 * MIB / 2) as usize];
    let down = vec![2u8; (MIB * 6 / 10) as usize];
    let at_b = async {
        let (mut send, mut recv, _) = b.offered(SOON).await.unwrap();
        write_frame(&mut send, &Frame::Accept).await.unwrap();
        let mut heard = Vec::new();
        recv.read_to_end(&mut heard).await.unwrap();
        send.write_all(&down).await.unwrap();
        send.shutdown().await.unwrap();
        heard.len()
    };
    let at_a = async {
        let (mut send, mut recv, answer) = a.open(B, "files").await;
        assert!(matches!(answer, Frame::Opened { .. }), "{answer:?}");
        send.write_all(&up).await.unwrap();
        send.shutdown().await.unwrap();
        let mut heard = Vec::new();
        recv.read_to_end(&mut heard).await.unwrap();
        heard.len()
    };
    let (at_b, at_a) = timeout(Duration::from_secs(30), async { tokio::join!(at_b, at_a) })
        .await
        .unwrap();
    assert_eq!((at_b, at_a), (up.len(), down.len()));
    assert!(
        ledger.settled.lock().is_empty(),
        "nothing is charged while the session lasts"
    );
    // End the session explicitly: it settles when it ends, however it ends.
    a.end().await;
    // 1.5 + 0.6 mebibytes carried: three started mebibytes.
    assert_eq!(ledger.settled(1).await, vec![(PAID.to_string(), 3)]);
}

#[tokio::test]
async fn a_paid_stream_ends_when_the_bytes_paid_for_are_spent() {
    let ledger = Ledger::new(MIB);
    let listener = paying(&ledger);
    let (a, _) = sign_in_paying(&listener, A, PAID).await;
    let mut b = Device::sign_in(&listener, B, "laptop").await;
    b.listen(&[A], &[]).await;

    let up = vec![1u8; (2 * MIB) as usize];
    let at_b = async {
        let (mut send, mut recv, _) = b.offered(SOON).await.unwrap();
        write_frame(&mut send, &Frame::Accept).await.unwrap();
        let mut heard = Vec::new();
        let _ = recv.read_to_end(&mut heard).await;
        heard.len() as u64
    };
    let at_a = async {
        let (mut send, _recv, _) = a.open(B, "files").await;
        let _ = send.write_all(&up).await;
        let _ = send.shutdown().await;
    };
    let (heard, ()) = timeout(Duration::from_secs(30), async { tokio::join!(at_b, at_a) })
        .await
        .unwrap();
    assert!(heard <= MIB, "carried {heard} bytes on a budget of {MIB}");
    // End the session explicitly: it settles when it ends, however it ends.
    a.end().await;
    assert_eq!(ledger.settled(1).await, vec![(PAID.to_string(), 1)]);
}

#[tokio::test]
async fn an_identity_pays_for_one_session_at_a_time() {
    let ledger = Ledger::new(MIB);
    let listener = paying(&ledger);
    let (_first, welcome) = sign_in_paying(&listener, A, PAID).await;
    assert!(
        matches!(welcome, Some(Frame::Welcome { .. })),
        "{welcome:?}"
    );
    let (_second, refused) = sign_in_paying(&listener, A, PAID).await;
    assert!(
        matches!(&refused, Some(Frame::Refused { reason }) if reason.contains("already pays")),
        "{refused:?}"
    );
}

/// Measured throughput and round-trip latency through one node, and through
/// two nodes joined in this process by an in-memory pipe (not over iroh).
/// It runs with the rest and prints the numbers under `--nocapture`; the
/// floor it asserts only catches a stream that has stalled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn measure_throughput_and_latency() {
    const ROUND_TRIPS: usize = 500;
    const BULK: usize = 16 << 20;
    for two_nodes in [false, true] {
        let (opener_side, target_side, via) = if two_nodes {
            let reaches = ReachesY::default();
            let to_y = reaches.0.clone();
            let x = between(4, Some(reaches));
            let y = Arc::new(between(4, None));
            let _ = to_y.set(y.clone());
            (Arc::new(x), y, Some(Y_NODE))
        } else {
            let one = Arc::new(listener());
            (one.clone(), one, None)
        };
        let a = Device::sign_in(&opener_side, A, "phone").await;
        let mut b = Device::sign_in(&target_side, B, "laptop").await;
        b.listen(&[A], &[]).await;

        // B echoes the first stream and counts the second.
        let serving = tokio::spawn(async move {
            let (mut send, mut recv, _) = b.offered(SOON).await.unwrap();
            write_frame(&mut send, &Frame::Accept).await.unwrap();
            let mut buf = [0u8; 64];
            for _ in 0..ROUND_TRIPS {
                recv.read_exact(&mut buf).await.unwrap();
                send.write_all(&buf).await.unwrap();
            }
            let (mut send, mut recv, _) = b.offered(SOON).await.unwrap();
            write_frame(&mut send, &Frame::Accept).await.unwrap();
            let mut total = 0u64;
            let mut chunk = vec![0u8; 64 << 10];
            loop {
                let n = recv.read(&mut chunk).await.unwrap().unwrap_or(0);
                if n == 0 {
                    break;
                }
                total += n as u64;
            }
            send.write_all(&total.to_le_bytes()).await.unwrap();
            send.shutdown().await.unwrap();
            b
        });

        let (mut send, mut recv, opened) = a.open_via(B, via, "measure").await;
        assert!(matches!(opened, Frame::Opened { .. }), "{opened:?}");
        let mut times = Vec::with_capacity(ROUND_TRIPS);
        let mut buf = [7u8; 64];
        for _ in 0..ROUND_TRIPS {
            let start = std::time::Instant::now();
            send.write_all(&buf).await.unwrap();
            recv.read_exact(&mut buf).await.unwrap();
            times.push(start.elapsed());
        }
        times.sort();
        let (p50, p99) = (times[ROUND_TRIPS / 2], times[ROUND_TRIPS * 99 / 100]);

        let (mut send, mut recv, _) = a.open_via(B, via, "measure").await;
        let data = vec![1u8; BULK];
        let start = std::time::Instant::now();
        send.write_all(&data).await.unwrap();
        send.shutdown().await.unwrap();
        let mut count = [0u8; 8];
        recv.read_exact(&mut count).await.unwrap();
        let elapsed = start.elapsed();
        assert_eq!(u64::from_le_bytes(count), BULK as u64);
        assert!(
            BULK as f64 / elapsed.as_secs_f64() > 1e6,
            "bulk carriage below 1 MB/s: {elapsed:?}"
        );
        let _b = serving.await.unwrap();
        println!(
            "app transport through {}: {:.1} MB/s ({} MiB in {:?}); 64-byte round trip p50 {:?}, p99 {:?}",
            if two_nodes { "two nodes" } else { "one node" },
            BULK as f64 / elapsed.as_secs_f64() / 1e6,
            BULK >> 20,
            elapsed,
            p50,
            p99,
        );
    }
}

/// Carries everything `from` has to send into `to`.
fn carry<F, T>(from: &mut rustls::ConnectionCommon<F>, to: &mut rustls::ConnectionCommon<T>) {
    let mut wire = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut wire).unwrap();
    }
    let mut rest = wire.as_slice();
    while !rest.is_empty() {
        to.read_tls(&mut rest).unwrap();
        to.process_new_packets().unwrap();
    }
}

/// The key exchange group a handshake with the listener's TLS settles on,
/// for a client that offers `offered`, in its own order of preference.
fn negotiated(
    offered: Vec<&'static dyn rustls::crypto::SupportedKxGroup>,
) -> Option<rustls::NamedGroup> {
    let certs = Arc::new(PinnedCerts::mint(vec!["localhost".to_string()], now()).unwrap());
    let served = certs.hashes()[0].sha256.clone();
    let server = with_alpn(tls_builder().unwrap().with_cert_resolver(certs));

    #[derive(Debug)]
    struct PinnedOnly(String, Arc<rustls::crypto::CryptoProvider>);
    impl rustls::client::danger::ServerCertVerifier for PinnedOnly {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            use sha2::{Digest, Sha256};
            if hex::encode(Sha256::digest(end_entity.as_ref())) == self.0 {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            } else {
                Err(rustls::Error::General("not the pinned certificate".into()))
            }
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.1.signature_verification_algorithms,
            )
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.1.signature_verification_algorithms,
            )
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.1.signature_verification_algorithms.supported_schemes()
        }
    }

    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = offered;
    let provider = Arc::new(provider);
    let mut client = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedOnly(served, provider)))
        .with_no_client_auth();
    client.alpn_protocols = vec![wtransport::tls::WEBTRANSPORT_ALPN.to_vec()];
    let mut client = rustls::ClientConnection::new(
        Arc::new(client),
        rustls::pki_types::ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut server = rustls::ServerConnection::new(Arc::new(server)).unwrap();
    while client.is_handshaking() || server.is_handshaking() {
        carry(&mut client, &mut server);
        carry(&mut server, &mut client);
    }
    server
        .negotiated_key_exchange_group()
        .map(|group| group.name())
}

#[test]
fn a_client_that_offers_the_hybrid_group_first_gets_it() {
    use rustls::crypto::aws_lc_rs::kx_group::{SECP256R1, X25519, X25519MLKEM768};
    // Browsers that support it send the hybrid key share first.
    assert_eq!(
        negotiated(vec![X25519MLKEM768, X25519]),
        Some(rustls::NamedGroup::X25519MLKEM768)
    );
    // A client that sends a classical key share is answered on it rather than
    // made to retry, and one without the hybrid group still connects.
    assert_eq!(
        negotiated(vec![X25519, SECP256R1, X25519MLKEM768]),
        Some(rustls::NamedGroup::X25519)
    );
    assert_eq!(negotiated(vec![X25519]), Some(rustls::NamedGroup::X25519));
}
