//! Streams between the devices of applications, carried by nodes.
//!
//! A device signs in to a node and opens a stream to a device of another
//! identity. The node the opener is signed in to carries the stream to the
//! target device, itself or through the target's node, and counts every byte
//! against the opener. What travels inside the stream is the application's:
//! the devices seal it end to end, and a node only moves it.
//!
//! Everything before the payload is a [`Frame`]: a little-endian `u32`
//! length and that many bytes of JSON, at most [`MAX_FRAME_BYTES`]. A session
//! starts on a control stream (`challenge`, `hello`, `welcome`, then `listen`
//! as often as the device changes who may reach it). Every other stream
//! starts with one frame each way (`open` answered by `opened` or `refused`;
//! `incoming` answered by `accept` or `decline`) and is raw bytes after that.
//!
//! Once a stream between two devices of one node is accepted, each end also
//! has a flow id (in `opened` and `incoming`): a datagram is the id,
//! little-endian, then the payload, and the node forwards it to the other
//! end under that end's id, counting it like the stream's bytes and dropping
//! it rather than making it wait.
//!
//! A stream to a device signed in to another node travels from node to node
//! under [`ALPN_APP_STREAM`]: the opener's node starts it with `carry`,
//! answered by `opened` or `refused` like an `open`. The node it reaches
//! counts the bytes against the node that carried it there.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use iroh::Endpoint;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::discovery::DiscoveryStore;
use crate::error::{IrohError, IrohResult};
use crate::request::read_request;

/// The most bytes one frame may take. A signed welcome carries an ML-DSA-65
/// signature (3309 bytes, about 4.4 KB in base64) beside a P-256 one, and a
/// paid hello a composite-signed payment credential: 4 KiB held neither.
pub const MAX_FRAME_BYTES: usize = 16 * 1024;

/// Bytes moved per read while a stream is carried.
const CARRY_CHUNK: usize = 64 * 1024;

/// A datagram for the flow `flow`: its id, little-endian, then the payload.
pub fn encode_datagram(flow: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend(flow.to_le_bytes());
    out.extend(payload);
    out
}

/// The flow a datagram is for and its payload.
pub fn decode_datagram(datagram: &[u8]) -> Option<(u32, &[u8])> {
    let (head, payload) = datagram.split_first_chunk::<4>()?;
    Some((u32::from_le_bytes(*head), payload))
}

/// The protocol a node carries a device's stream to another node under.
pub const ALPN_APP_STREAM: &[u8] = b"tenzro/app-stream/1";

/// The receiving half of a stream between nodes.
pub type BoxedRead = Box<dyn AsyncRead + Send + Unpin>;

/// The sending half of a stream between nodes.
pub type BoxedWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// Serves the streams other nodes carry to devices signed in to this one.
pub trait PeerStreams: Send + Sync + 'static {
    /// Serves one stream from the node `peer` (its machine DID).
    fn serve(
        &self,
        peer: String,
        recv: BoxedRead,
        send: BoxedWrite,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
}

/// Opens streams under [`ALPN_APP_STREAM`] to other nodes by machine DID,
/// through the endpoint records `discovery` holds, keeping one connection to
/// each.
pub struct PeerDialer {
    endpoint: Endpoint,
    discovery: Arc<DiscoveryStore>,
    connections: Mutex<HashMap<String, Connection>>,
}

impl PeerDialer {
    /// Dials from `endpoint`.
    pub fn new(endpoint: Endpoint, discovery: Arc<DiscoveryStore>) -> Self {
        Self {
            endpoint,
            discovery,
            connections: Mutex::new(HashMap::new()),
        }
    }

    /// A new stream to the node `did`.
    pub async fn open(&self, did: &str) -> IrohResult<(BoxedRead, BoxedWrite)> {
        let connection = self.connection(did).await?;
        let (send, recv) = crate::bounded::open_bi(&connection, crate::bounded::BACKSTOP)
            .await
            .map_err(|e| IrohError::Backend(format!("{did} took no stream: {e}")))?;
        Ok((Box::new(recv), Box::new(send)))
    }

    async fn connection(&self, did: &str) -> IrohResult<Connection> {
        if let Some(open) = self.connections.lock().get(did)
            && open.close_reason().is_none()
        {
            return Ok(open.clone());
        }
        let record = self
            .discovery
            .lookup(did)
            .ok_or_else(|| IrohError::Backend(format!("{did} is not a node this one knows")))?;
        let addr = crate::identity_transport::endpoint_addr(&record)?;
        let connection = crate::bounded::connect(
            &self.endpoint,
            addr,
            ALPN_APP_STREAM,
            crate::bounded::BACKSTOP,
        )
        .await
        .map_err(|e| IrohError::Backend(format!("{did} could not be reached: {e}")))?;
        self.connections
            .lock()
            .insert(did.to_string(), connection.clone());
        Ok(connection)
    }
}

/// [`ALPN_APP_STREAM`] on the router. The identity gate admits only
/// registered machines to it; a connection whose endpoint no verified record
/// names is closed.
#[derive(Clone)]
pub struct AppStreamProtocol {
    streams: Arc<dyn PeerStreams>,
    discovery: Arc<DiscoveryStore>,
}

impl std::fmt::Debug for AppStreamProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AppStreamProtocol")
    }
}

impl AppStreamProtocol {
    /// Serves `streams`, naming each peer by the record `discovery` holds.
    pub fn new(streams: Arc<dyn PeerStreams>, discovery: Arc<DiscoveryStore>) -> Self {
        Self { streams, discovery }
    }
}

impl ProtocolHandler for AppStreamProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let Some(peer) = self
            .discovery
            .naming(conn.remote_id())
            .map(|record| record.machine_did())
        else {
            conn.close(1u32.into(), b"no machine identity names this endpoint");
            return Ok(());
        };
        while let Ok((send, recv)) = conn.accept_bi().await {
            tokio::spawn(
                self.streams
                    .serve(peer.clone(), Box::new(recv), Box::new(send)),
            );
        }
        Ok(())
    }
}

/// Domain of the digest a node signs a welcome over.
pub const WELCOME_DOMAIN: &[u8] = b"tenzro/app-transport/welcome/v1";

/// FIPS 204 context of a welcome's ML-DSA-65 signature.
pub const WELCOME_PQ_CONTEXT: &[u8] = b"tenzro/app-transport/welcome";

/// The digest a node signs a welcome over: the session's nonce, and who the
/// node took the device for until when. The nonce is fresh per session, so a
/// welcome from one session does not pass on another.
pub fn welcome_digest(nonce: &str, did: &str, device: &str, expires_at: u64) -> [u8; 32] {
    let mut preimage = WELCOME_DOMAIN.to_vec();
    for text in [nonce, did, device] {
        preimage.extend((text.len() as u64).to_be_bytes());
        preimage.extend(text.as_bytes());
    }
    preimage.extend(expires_at.to_be_bytes());
    tenzro_crypto::hash::sha256(&preimage).to_bytes()
}

/// The DPoP `htu` a device's proof of possession carries when it signs in
/// to a session: the session's nonce, as `tenzro-app://{nonce}`, with `htm`
/// `POST`. A proof made for one session is no use on another.
pub fn sign_in_htu(nonce: &str) -> String {
    format!("tenzro-app://{nonce}")
}

/// The label a sign-in's TLS binding is exported under (RFC 5705).
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-tenzro-app-transport-sign-in";

/// Bytes of keying material a binding carries.
pub const EXPORTER_BYTES: usize = 32;

/// The URI a sign-in proof names when it is bound to the TLS session:
/// the nonce and the exported keying material (hex).
pub fn sign_in_htu_bound(nonce: &str, binding: &str) -> String {
    format!("tenzro-app://{nonce}/{binding}")
}

/// What is said on a session's control stream and at the head of a stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Frame {
    /// Node to device, first on the control stream: the nonce the device's
    /// proof of possession must carry.
    Challenge {
        /// Made by the node for this session alone.
        nonce: String,
    },
    /// Device to node: its access token and a proof of possession made for
    /// this session's challenge. Sent again before the token runs out to
    /// keep the session.
    Hello {
        /// The access token this node issued to the device.
        access_token: String,
        /// The proof of possession, made over this session's nonce.
        dpop: String,
        /// A payment credential (JSON) answering the node's
        /// `payment_required`, when the node asks payment for carriage.
        #[serde(skip_serializing_if = "Option::is_none")]
        payment: Option<String>,
        /// Keying material (hex) the device exported from this session's
        /// TLS secrets under [`EXPORTER_LABEL`] with the nonce as context;
        /// with it, the proof names [`sign_in_htu_bound`] and holds only on
        /// this TLS session. A device that cannot export (a browser) leaves
        /// it out.
        #[serde(skip_serializing_if = "Option::is_none")]
        binding: Option<String>,
    },
    /// Node to device: the access policy asks payment for carriage. The
    /// device signs in again with a credential for `challenge` in `payment`.
    PaymentRequired {
        /// The payment challenge (JSON); its amount is the most the session
        /// may be charged.
        challenge: String,
        /// The price of one mebibyte carried, both directions together, in
        /// the smallest unit of `asset`.
        price: String,
        /// The asset the price is in.
        asset: String,
    },
    /// Node to device: who the node took it for, and until when.
    Welcome {
        /// The identity the token names.
        did: String,
        /// The device: the thumbprint of the key the token is bound to.
        device: String,
        /// When the token, and with it the session, ends; seconds since the
        /// epoch.
        expires_at: u64,
        /// ECDSA P-256 signature (`r || s`, base64url) over
        /// [`welcome_digest`] by the key the node's access tokens and its
        /// pinned certificate publication verify under.
        signature: String,
        /// ML-DSA-65 signature (base64url) over [`welcome_digest`] under the
        /// context [`WELCOME_PQ_CONTEXT`], by the key the node's DID document
        /// names `#pq-key-1`.
        pq_signature: String,
    },
    /// Device to node: who may open streams to this device from now on. A
    /// sender is let through when `from` names its identity or `apps` names
    /// the label it opens with. Both empty: nobody.
    Listen {
        /// Identities that may open any stream to this device.
        from: Vec<String>,
        /// Application labels anyone may open a stream with.
        apps: Vec<String>,
    },
    /// Node to device: the last `listen` is in force.
    Listening,
    /// Device to node, at the head of a stream: carry this stream to a device
    /// of another identity.
    Open {
        /// The identity to reach.
        to: String,
        /// The device of that identity to reach; any that takes the stream
        /// when absent.
        device: Option<String>,
        /// The node the target is signed in to, when it is not this one.
        via: Option<String>,
        /// The application label the stream is opened with.
        app: String,
    },
    /// Node to device, at the head of a stream: somebody opened this stream
    /// to it.
    Incoming {
        /// The identity that opened it.
        from: String,
        /// The device it opened it from.
        device: String,
        /// The node that carried it here, when it is not this one.
        via: Option<String>,
        /// The application label it was opened with.
        app: String,
        /// The flow datagrams for this stream travel under, once accepted;
        /// none for a stream from another node.
        #[serde(skip_serializing_if = "Option::is_none")]
        flow: Option<u32>,
    },
    /// Node to node, at the head of a stream under [`ALPN_APP_STREAM`]: a
    /// device signed in to the dialling node opens this stream to a device
    /// signed in to this one.
    Carry {
        /// The identity that opened it.
        from: String,
        /// The device it opened it from.
        from_device: String,
        /// The identity to reach.
        to: String,
        /// The device of that identity to reach; any that takes the stream
        /// when absent.
        device: Option<String>,
        /// The application label it was opened with.
        app: String,
    },
    /// Target device to node: it takes the stream.
    Accept,
    /// Target device to node: it does not.
    Decline,
    /// Node to opener: the stream reaches a device; bytes follow.
    Opened {
        /// The device that took it.
        device: String,
        /// The flow datagrams for this stream travel under; none for a
        /// stream through another node.
        #[serde(skip_serializing_if = "Option::is_none")]
        flow: Option<u32>,
    },
    /// Node to device: no.
    Refused {
        /// Why.
        reason: String,
    },
}

/// Reads one frame.
pub async fn read_frame<R>(recv: &mut R) -> IrohResult<Frame>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let bytes = read_request(recv, MAX_FRAME_BYTES).await?;
    serde_json::from_slice(&bytes).map_err(|e| IrohError::Backend(format!("frame: {e}")))
}

/// Writes one frame.
pub async fn write_frame<W>(send: &mut W, frame: &Frame) -> IrohResult<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let bytes = serde_json::to_vec(frame).map_err(|e| IrohError::Backend(format!("frame: {e}")))?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(IrohError::Backend(format!(
            "frame of {} bytes exceeds {MAX_FRAME_BYTES}",
            bytes.len()
        )));
    }
    send.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

/// What one identity has had carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Usage {
    /// Streams it opened that reached their target.
    pub streams: u64,
    /// Bytes carried from it.
    pub bytes_sent: u64,
    /// Bytes carried to it.
    pub bytes_received: u64,
}

#[derive(Debug)]
struct Account {
    usage: Usage,
    /// Bytes it may move now; negative while it owes time.
    allowance: f64,
    at: Instant,
    /// Bytes it has paid to move and not moved yet, when it pays.
    budget: Option<u64>,
}

/// Which way bytes move on a carried stream, seen from who pays for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Sent,
    Received,
}

/// When a carried stream last moved a byte, either way.
struct Activity {
    start: Instant,
    last_ms: std::sync::atomic::AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last_ms: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn moved(&self) {
        let now = self.start.elapsed().as_millis() as u64;
        self.last_ms
            .store(now, std::sync::atomic::Ordering::Relaxed);
    }

    fn quiet_for(&self) -> Duration {
        let last = self.last_ms.load(std::sync::atomic::Ordering::Relaxed);
        self.start
            .elapsed()
            .saturating_sub(Duration::from_millis(last))
    }
}

/// Counts what each identity has had carried and holds each to a byte rate.
#[derive(Debug)]
pub struct ByteMeter {
    bytes_per_second: u64,
    burst_bytes: u64,
    accounts: Mutex<HashMap<String, Account>>,
    /// How long a carried stream may move nothing either way before it ends.
    idle: Option<Duration>,
}

impl ByteMeter {
    /// A meter that lets each identity move `bytes_per_second`, both
    /// directions together, and `burst_bytes` at once after a pause.
    pub fn new(bytes_per_second: u64, burst_bytes: u64) -> Self {
        Self {
            bytes_per_second: bytes_per_second.max(1),
            burst_bytes: burst_bytes.max(CARRY_CHUNK as u64),
            accounts: Mutex::new(HashMap::new()),
            idle: None,
        }
    }

    /// Ends a carried stream that moves nothing either way for `idle`.
    pub fn with_idle(mut self, idle: Duration) -> Self {
        self.idle = Some(idle);
        self
    }

    fn account<'a>(
        &self,
        accounts: &'a mut HashMap<String, Account>,
        who: &str,
        now: Instant,
    ) -> &'a mut Account {
        accounts.entry(who.to_string()).or_insert(Account {
            usage: Usage::default(),
            allowance: self.burst_bytes as f64,
            at: now,
            budget: None,
        })
    }

    /// Counts a stream `who` opened that reached its target.
    pub fn opened(&self, who: &str) {
        let mut accounts = self.accounts.lock();
        self.account(&mut accounts, who, Instant::now())
            .usage
            .streams += 1;
    }

    /// Counts a datagram of `bytes` for `who` when it may move now, within
    /// its rate and what it paid for; otherwise counts nothing and says no.
    /// A datagram is never made to wait.
    pub fn try_datagram(&self, who: &str, sent: bool, bytes: u64) -> bool {
        let now = Instant::now();
        let mut accounts = self.accounts.lock();
        let account = self.account(&mut accounts, who, now);
        let earned = now.duration_since(account.at).as_secs_f64() * self.bytes_per_second as f64;
        let allowance = (account.allowance + earned).min(self.burst_bytes as f64);
        if allowance < bytes as f64 || account.budget.is_some_and(|budget| budget < bytes) {
            return false;
        }
        account.allowance = allowance - bytes as f64;
        account.at = now;
        if let Some(budget) = account.budget.as_mut() {
            *budget -= bytes;
        }
        if sent {
            account.usage.bytes_sent += bytes;
        } else {
            account.usage.bytes_received += bytes;
        }
        true
    }

    /// Holds `who` to `bytes` more carried, both directions together, until
    /// [`Self::lift_budget`]: past it a stream `who` pays for ends.
    pub fn set_budget(&self, who: &str, bytes: u64) {
        let mut accounts = self.accounts.lock();
        self.account(&mut accounts, who, Instant::now()).budget = Some(bytes);
    }

    /// Lets `who` move bytes without a budget again.
    pub fn lift_budget(&self, who: &str) {
        if let Some(account) = self.accounts.lock().get_mut(who) {
            account.budget = None;
        }
    }

    /// Counts `bytes` moved for `who` at `now` and says how long the stream
    /// must wait before it moves them, or `None` when they are past what
    /// `who` paid for: they are then neither moved nor counted.
    fn charge(
        &self,
        who: &str,
        direction: Direction,
        bytes: u64,
        now: Instant,
    ) -> Option<Duration> {
        let mut accounts = self.accounts.lock();
        let account = self.account(&mut accounts, who, now);
        if let Some(budget) = account.budget.as_mut() {
            *budget = budget.checked_sub(bytes)?;
        }
        let earned = now.duration_since(account.at).as_secs_f64() * self.bytes_per_second as f64;
        account.allowance = (account.allowance + earned).min(self.burst_bytes as f64);
        account.at = now;
        account.allowance -= bytes as f64;
        match direction {
            Direction::Sent => account.usage.bytes_sent += bytes,
            Direction::Received => account.usage.bytes_received += bytes,
        }
        Some(if account.allowance >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-account.allowance / self.bytes_per_second as f64)
        })
    }

    /// What `who` has had carried since the node started.
    pub fn usage(&self, who: &str) -> Usage {
        self.accounts
            .lock()
            .get(who)
            .map(|a| a.usage)
            .unwrap_or_default()
    }

    /// What every identity has had carried since the node started, by
    /// identity.
    pub fn all(&self) -> Vec<(String, Usage)> {
        let mut all: Vec<_> = self
            .accounts
            .lock()
            .iter()
            .map(|(who, a)| (who.clone(), a.usage))
            .collect();
        all.sort_by(|a, b| a.0.cmp(&b.0));
        all
    }

    /// Moves bytes one way until the reader ends, counting them for `payer`
    /// and holding them to its rate, then ends the writer.
    async fn pump<R, W>(
        &self,
        payer: &str,
        direction: Direction,
        mut from: R,
        mut to: W,
        activity: &Activity,
    ) -> std::io::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut buf = vec![0u8; CARRY_CHUNK];
        loop {
            let n = match self.idle {
                None => from.read(&mut buf).await?,
                Some(idle) => loop {
                    match tokio::time::timeout(idle, from.read(&mut buf)).await {
                        Ok(read) => break read?,
                        // Quiet this way; the stream ends only when the other
                        // way has been quiet as long.
                        Err(_) if activity.quiet_for() >= idle => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "the stream moved nothing for too long",
                            ));
                        }
                        Err(_) => {}
                    }
                },
            };
            activity.moved();
            if n == 0 {
                return to.shutdown().await;
            }
            let Some(wait) = self.charge(payer, direction, n as u64, Instant::now()) else {
                return Err(std::io::Error::other("the bytes paid for are spent"));
            };
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
            to.write_all(&buf[..n]).await?;
        }
    }

    /// Carries a stream between its opener and its target until both
    /// directions end, counting every byte for `payer`. An end in one
    /// direction is passed on and the other direction goes on; a failure in
    /// either ends both.
    pub async fn carry<OR, OW, TR, TW>(
        &self,
        payer: &str,
        opener: (OR, OW),
        target: (TR, TW),
    ) -> std::io::Result<()>
    where
        OR: AsyncRead + Unpin,
        OW: AsyncWrite + Unpin,
        TR: AsyncRead + Unpin,
        TW: AsyncWrite + Unpin,
    {
        let activity = Activity::new();
        tokio::try_join!(
            self.pump(payer, Direction::Sent, opener.0, target.1, &activity),
            self.pump(payer, Direction::Received, target.0, opener.1, &activity),
        )
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_frame_reads_back_as_it_was_written() {
        let frames = [
            Frame::Challenge {
                nonce: "n".to_string(),
            },
            Frame::Open {
                to: "did:tenzro:human:b".to_string(),
                device: None,
                via: Some("did:tenzro:machine:n2".to_string()),
                app: "messenger".to_string(),
            },
            Frame::Listen {
                from: vec!["did:tenzro:human:a".to_string()],
                apps: Vec::new(),
            },
            Frame::Hello {
                access_token: "tok".to_string(),
                dpop: "proof".to_string(),
                payment: Some("{}".to_string()),
                binding: Some("ab".repeat(32)),
            },
            Frame::PaymentRequired {
                challenge: "{}".to_string(),
                price: "3".to_string(),
                asset: "TNZO".to_string(),
            },
            Frame::Carry {
                from: "did:tenzro:human:a".to_string(),
                from_device: "phone".to_string(),
                to: "did:tenzro:human:b".to_string(),
                device: None,
                app: "messenger".to_string(),
            },
            Frame::Welcome {
                did: "did:tenzro:human:a".to_string(),
                device: "phone".to_string(),
                expires_at: 1_800_000_000,
                signature: "c2ln".to_string(),
                pq_signature: "cHE".to_string(),
            },
            Frame::Accept,
        ];
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        for frame in &frames {
            write_frame(&mut a, frame).await.unwrap();
        }
        for frame in &frames {
            assert_eq!(&read_frame(&mut b).await.unwrap(), frame);
        }
    }

    #[tokio::test]
    async fn a_frame_is_json_behind_a_little_endian_length() {
        let mut wire = Vec::new();
        write_frame(&mut wire, &Frame::Accept).await.unwrap();
        let body = br#"{"type":"accept"}"#;
        assert_eq!(&wire[..4], &(body.len() as u32).to_le_bytes());
        assert_eq!(&wire[4..], body);
    }

    #[tokio::test]
    async fn an_oversized_or_unknown_frame_is_refused() {
        let long = Frame::Refused {
            reason: "x".repeat(MAX_FRAME_BYTES),
        };
        assert!(write_frame(&mut Vec::new(), &long).await.is_err());

        let mut announced = ((MAX_FRAME_BYTES + 1) as u32).to_le_bytes().to_vec();
        announced.extend_from_slice(b"{}");
        assert!(read_frame(&mut announced.as_slice()).await.is_err());

        for body in [
            br#"{"type":"opened","device":"d","extra":1}"#.as_slice(),
            br#"{"type":"something_else"}"#.as_slice(),
            br#"{"type":"open","to":"did:tenzro:human:b"}"#.as_slice(),
        ] {
            let mut wire = (body.len() as u32).to_le_bytes().to_vec();
            wire.extend_from_slice(body);
            assert!(read_frame(&mut wire.as_slice()).await.is_err());
        }
    }

    #[tokio::test]
    async fn carried_bytes_arrive_whole_and_are_counted_for_the_payer() {
        let meter = ByteMeter::new(1 << 30, 1 << 30);
        let (opener, opener_at_node) = tokio::io::duplex(8 * 1024);
        let (target, target_at_node) = tokio::io::duplex(8 * 1024);
        let up: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        let down: Vec<u8> = (0..70_000u32).map(|i| (i * 7) as u8).collect();

        let carried = async {
            meter
                .carry(
                    "did:tenzro:human:a",
                    tokio::io::split(opener_at_node),
                    tokio::io::split(target_at_node),
                )
                .await
        };
        let talk = |mut end: tokio::io::DuplexStream, say: Vec<u8>| async move {
            let (mut read, mut write) = tokio::io::split(&mut end);
            let mut heard = Vec::new();
            let (_, _) = tokio::join!(
                async {
                    write.write_all(&say).await.unwrap();
                    write.shutdown().await.unwrap();
                },
                async { read.read_to_end(&mut heard).await.unwrap() },
            );
            heard
        };
        let (result, at_opener, at_target) = tokio::join!(
            carried,
            talk(opener, up.clone()),
            talk(target, down.clone())
        );
        result.unwrap();
        assert_eq!(at_target, up);
        assert_eq!(at_opener, down);
        assert_eq!(
            meter.usage("did:tenzro:human:a"),
            Usage {
                streams: 0,
                bytes_sent: up.len() as u64,
                bytes_received: down.len() as u64,
            }
        );
        assert_eq!(meter.usage("did:tenzro:human:b"), Usage::default());
    }

    #[test]
    fn an_identity_is_held_to_its_byte_rate_in_both_directions_together() {
        let chunk = CARRY_CHUNK as u64;
        let meter = ByteMeter::new(chunk, 2 * chunk);
        let start = Instant::now();
        let who = "did:tenzro:human:a";
        assert_eq!(
            meter.charge(who, Direction::Sent, chunk, start),
            Some(Duration::ZERO)
        );
        assert_eq!(
            meter.charge(who, Direction::Received, chunk, start),
            Some(Duration::ZERO)
        );
        assert_eq!(
            meter.charge(who, Direction::Sent, chunk, start),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            meter.charge(who, Direction::Sent, chunk, start),
            Some(Duration::from_secs(2))
        );
        // Another identity is not held by this one's use.
        assert_eq!(
            meter.charge("did:tenzro:human:b", Direction::Sent, chunk, start),
            Some(Duration::ZERO)
        );
        // Time pays the debt back and refills no further than the burst.
        let later = start + Duration::from_secs(60);
        assert_eq!(
            meter.charge(who, Direction::Sent, 2 * chunk, later),
            Some(Duration::ZERO)
        );
        assert_eq!(
            meter.charge(who, Direction::Sent, chunk, later),
            Some(Duration::from_secs(1))
        );
        assert_eq!(meter.usage(who).bytes_sent, 6 * chunk);
        assert_eq!(meter.usage(who).bytes_received, chunk);
    }

    #[test]
    fn a_paying_identity_moves_no_more_than_its_budget() {
        let chunk = CARRY_CHUNK as u64;
        let meter = ByteMeter::new(1 << 40, 1 << 40);
        let start = Instant::now();
        let who = "did:tenzro:human:a";
        meter.set_budget(who, 3 * chunk);
        assert!(meter.charge(who, Direction::Sent, chunk, start).is_some());
        assert!(
            meter
                .charge(who, Direction::Received, 2 * chunk, start)
                .is_some()
        );
        assert_eq!(meter.charge(who, Direction::Sent, 1, start), None);
        // What was refused was neither moved nor counted.
        assert_eq!(meter.usage(who).bytes_sent, chunk);
        meter.lift_budget(who);
        assert!(meter.charge(who, Direction::Sent, chunk, start).is_some());
    }

    #[tokio::test]
    async fn a_stream_quiet_both_ways_ends_and_one_moving_one_way_does_not() {
        // The idle bound is far above the sender's pace, so a test thread
        // that is not scheduled for a few hundred milliseconds on a loaded
        // host does not read as a quiet stream.
        let meter = ByteMeter::new(1 << 40, 1 << 40).with_idle(Duration::from_secs(1));
        let who = "did:tenzro:human:a";

        let (opener, _opener_far) = tokio::io::duplex(1024);
        let (target, _target_far) = tokio::io::duplex(1024);
        let quiet = tokio::time::timeout(
            Duration::from_secs(10),
            meter.carry(who, tokio::io::split(opener), tokio::io::split(target)),
        )
        .await
        .expect("a quiet stream ends");
        assert_eq!(quiet.unwrap_err().kind(), std::io::ErrorKind::TimedOut);

        // Bytes one way every 50 ms for 1.5 s, longer than the idle bound,
        // keep it open, though the other way says nothing; then the sender
        // ends and so does the stream.
        let (opener, mut opener_far) = tokio::io::duplex(1024);
        let (target, mut target_far) = tokio::io::duplex(1024);
        let sending = async move {
            for _ in 0..30 {
                opener_far.write_all(b"x").await.unwrap();
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            opener_far.shutdown().await.unwrap();
            opener_far
        };
        let reading = async move {
            let mut got = Vec::new();
            target_far.read_to_end(&mut got).await.unwrap();
            target_far.shutdown().await.unwrap();
            got.len()
        };
        let (carried, _, got) = tokio::join!(
            meter.carry(who, tokio::io::split(opener), tokio::io::split(target)),
            sending,
            reading,
        );
        assert!(carried.is_ok(), "{carried:?}");
        assert_eq!(got, 30);
    }

    #[tokio::test]
    async fn a_stream_past_the_budget_ends() {
        let meter = ByteMeter::new(1 << 40, 1 << 40);
        let who = "did:tenzro:human:a";
        meter.set_budget(who, 10);
        let (opener, mut opener_far) = tokio::io::duplex(1024);
        let (target, mut target_far) = tokio::io::duplex(1024);
        opener_far.write_all(&[7u8; 64]).await.unwrap();
        let (or, ow) = tokio::io::split(opener);
        let (tr, tw) = tokio::io::split(target);
        let carried = meter.carry(who, (or, ow), (tr, tw)).await;
        assert!(carried.is_err());
        let mut got = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_millis(200), target_far.read(&mut got)).await;
        assert!(
            !matches!(n, Ok(Ok(1))),
            "nothing past the budget reached the target"
        );
        assert_eq!(meter.usage(who).bytes_sent, 0);
    }

    #[test]
    fn opened_streams_are_counted_per_identity() {
        let meter = ByteMeter::new(1, 1);
        meter.opened("did:tenzro:human:a");
        meter.opened("did:tenzro:human:a");
        meter.opened("did:tenzro:human:b");
        assert_eq!(
            meter.all(),
            vec![
                (
                    "did:tenzro:human:a".to_string(),
                    Usage {
                        streams: 2,
                        ..Usage::default()
                    }
                ),
                (
                    "did:tenzro:human:b".to_string(),
                    Usage {
                        streams: 1,
                        ..Usage::default()
                    }
                ),
            ]
        );
    }

    /// The same vector the TypeScript client's test pins.
    #[test]
    fn a_welcome_digest_matches_the_shared_vector() {
        let digest = welcome_digest("n1", "did:tenzro:human:a", "phone", 1_800_000_000);
        assert_eq!(
            hex::encode(digest),
            "ee32d5fe974bb82fd5895ad0e237a9d282a0cae8a425a75edc4ba7e8fc19dd94"
        );
    }

    #[test]
    fn a_welcome_digest_changes_with_every_field_it_covers() {
        let base = welcome_digest("n", "did:tenzro:human:a", "phone", 10);
        for other in [
            welcome_digest("m", "did:tenzro:human:a", "phone", 10),
            welcome_digest("n", "did:tenzro:human:b", "phone", 10),
            welcome_digest("n", "did:tenzro:human:a", "laptop", 10),
            welcome_digest("n", "did:tenzro:human:a", "phone", 11),
            // Lengths are framed: moving a byte between fields is not the same.
            welcome_digest("nd", "id:tenzro:human:a", "phone", 10),
        ] {
            assert_ne!(base, other);
        }
    }

    #[test]
    fn a_hello_without_a_payment_leaves_the_field_off_the_wire() {
        let hello = Frame::Hello {
            access_token: "tok".to_string(),
            dpop: "proof".to_string(),
            payment: None,
            binding: None,
        };
        let wire = serde_json::to_string(&hello).unwrap();
        assert_eq!(
            wire,
            r#"{"type":"hello","access_token":"tok","dpop":"proof"}"#
        );
        assert_eq!(serde_json::from_str::<Frame>(&wire).unwrap(), hello);
    }
}
