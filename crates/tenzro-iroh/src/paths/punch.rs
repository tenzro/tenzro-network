//! Direct paths across an endpoint-dependent (symmetric) NAT.
//!
//! Hole punching through QUIC finds a direct path when the NAT on at least
//! one side keeps the same public port for every peer. Behind an
//! endpoint-dependent NAT it does not: the port the NAT gives the hard side
//! towards a peer is unknown until a packet uses it. This module finds one
//! by the birthday method: the hard side opens [`HARD_SOCKETS`] sockets and
//! sends from each towards the easy side's address, so its NAT opens as
//! many mappings towards that one address; the easy side sends
//! [`EASY_PROBES`] probes to random ports at the hard side's public IP.
//! With 256 mappings and 1,024 probes over the 64,512 ports a NAT uses, a
//! probe lands on an open mapping with probability about 98%. The first
//! probe through is answered, and that pair of sockets becomes a path.
//! Both sides of a symmetric pair cannot be crossed this way; that pair
//! stays on a peer relay.
//!
//! The work is bounded: one attempt per peer per [`RETRY_AFTER`], one at a
//! time on each node, at most 1,024 probes paced over about two seconds,
//! sockets held for [`ATTEMPT`] and closed. The hard side asks the easy side
//! over an ordinary connection (`tenzro/punch/1`) before anything is sent,
//! and the easy side answers only while it is not already in an attempt.
//!
//! The easy side learns the public address of its punch socket from a peer
//! relay it reaches directly: the forwarder answers a UDP probe with the
//! address it came from.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{EndpointAddr, EndpointId};
use iroh_base::CustomAddr;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;

use super::{PATHS_TRANSPORT_ID, PathStats, Paths};

/// ALPN of the punch request.
pub const ALPN_PUNCH: &[u8] = b"tenzro/punch/1";

/// Address kind: a punched UDP path to a peer.
pub(super) const KIND_PUNCHED: u8 = 2;

/// Sockets the hard side opens.
pub const HARD_SOCKETS: usize = 256;

/// Probes the easy side sends.
pub const EASY_PROBES: usize = 1_024;

/// How long one attempt runs.
pub const ATTEMPT: Duration = Duration::from_secs(5);

/// How long before the same peer is tried again.
pub const RETRY_AFTER: Duration = Duration::from_secs(600);

/// Lowest port a NAT maps to.
const LOW_PORT: u16 = 1_024;

/// Packet tags on a punch socket.
const TAG_DATA: u8 = 0;
const TAG_KEEPALIVE: u8 = 1;
const TAG_PROBE: u8 = 2;
const TAG_ACK: u8 = 3;
const TAG_OBSERVE: u8 = 4;
const TAG_OBSERVED: u8 = 5;

/// How often a punched path is kept warm, well inside the two minutes a NAT
/// keeps a UDP mapping (RFC 4787 REQ-5).
const KEEPALIVE: Duration = Duration::from_secs(15);

/// The custom address of the punched path to `peer`.
pub fn punched_addr(peer: EndpointId) -> CustomAddr {
    let mut data = Vec::with_capacity(33);
    data.push(KIND_PUNCHED);
    data.extend_from_slice(peer.as_bytes());
    CustomAddr::from_parts(PATHS_TRANSPORT_ID, &data)
}

/// The peer of a punched path address.
pub fn parse_punched_addr(addr: &CustomAddr) -> Option<EndpointId> {
    let data = addr.data();
    if addr.id() != PATHS_TRANSPORT_ID || data.len() != 33 || data[0] != KIND_PUNCHED {
        return None;
    }
    EndpointId::from_bytes(data[1..33].try_into().ok()?).ok()
}

/// How this node's NAT maps ports, as its peers report it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatSide {
    /// Not known yet.
    Unknown,
    /// The same public port for every peer, or no NAT.
    Easy,
    /// A different public port for every peer, at this public IP.
    Hard(IpAddr),
}

/// One punched path: the socket it uses and the peer's address on it.
#[derive(Debug)]
pub(super) struct Punched {
    socket: Arc<UdpSocket>,
    remote: SocketAddr,
}

impl Punched {
    pub(super) fn send(&self, packet: &[u8]) -> bool {
        let mut buf = Vec::with_capacity(packet.len() + 1);
        buf.push(TAG_DATA);
        buf.extend_from_slice(packet);
        self.socket.try_send_to(&buf, self.remote).is_ok()
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum Message {
    /// From the hard side: punch towards me at this public IP.
    Request { hard_ip: IpAddr, nonce: [u8; 16] },
    /// From the easy side: my punch socket's public address.
    Accept { easy: SocketAddr },
    /// From the easy side: not now.
    Refuse(String),
}

/// The punch state of one node.
#[derive(Debug, Default)]
pub(super) struct PunchState {
    nat: Mutex<Option<NatSide>>,
    /// The easy side's one punch socket, bound on first use.
    socket: tokio::sync::OnceCell<Arc<UdpSocket>>,
    /// The punch socket's public address, once a forwarder reported it.
    public: Mutex<Option<SocketAddr>>,
    /// Paths punched, by peer.
    pub(super) punched: Mutex<HashMap<EndpointId, Arc<Punched>>>,
    /// Last attempt per peer.
    attempts: Mutex<HashMap<EndpointId, Instant>>,
    /// An attempt in progress on the easy side: its nonce and the peer.
    easy_attempt: Mutex<Option<([u8; 16], EndpointId, IpAddr)>>,
    /// One attempt at a time.
    busy: tokio::sync::Mutex<()>,
    /// Pending observe answers by nonce.
    observing: Mutex<HashMap<[u8; 16], tokio::sync::oneshot::Sender<SocketAddr>>>,
    /// The last outcomes, newest last.
    log: Mutex<std::collections::VecDeque<String>>,
}

impl PunchState {
    fn note(&self, line: String) {
        let mut log = self.log.lock();
        if log.len() >= 16 {
            log.pop_front();
        }
        log.push_back(line);
    }
}

impl Paths {
    /// Tells the transport how this node's NAT maps ports.
    pub fn set_nat(&self, side: NatSide) {
        *self.inner.punch.nat.lock() = Some(side);
    }

    /// How this node's NAT maps ports, as last set.
    pub fn nat_side(&self) -> NatSide {
        self.nat()
    }

    fn nat(&self) -> NatSide {
        self.inner.punch.nat.lock().unwrap_or(NatSide::Unknown)
    }

    /// The last punch attempts and their outcomes, newest last.
    pub fn punch_log(&self) -> Vec<String> {
        self.inner.punch.log.lock().iter().cloned().collect()
    }

    /// The peers this node has a punched path to.
    pub fn punched_peers(&self) -> Vec<EndpointId> {
        self.inner.punch.punched.lock().keys().copied().collect()
    }

    /// The easy side's punch socket, bound on first use, with its receive
    /// loop.
    async fn punch_socket(&self) -> io::Result<Arc<UdpSocket>> {
        let this = self.clone();
        self.inner
            .punch
            .socket
            .get_or_try_init(|| async move {
                let socket = Arc::new(UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).await?);
                tokio::spawn(this.clone().receive_loop(socket.clone(), None));
                Ok(socket)
            })
            .await
            .cloned()
    }

    /// The public address of the punch socket, asked of a forwarder this
    /// node reaches on a direct path.
    async fn punch_public(&self) -> Option<SocketAddr> {
        if let Some(a) = *self.inner.punch.public.lock() {
            return Some(a);
        }
        let socket = self.punch_socket().await.ok()?;
        for (conn, ip) in self.direct_forwarders() {
            let Some(port) = observe_port(&conn).await else {
                continue;
            };
            let nonce: [u8; 16] = rand::random();
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.inner.punch.observing.lock().insert(nonce, tx);
            let mut probe = vec![TAG_OBSERVE];
            probe.extend_from_slice(&nonce);
            for _ in 0..3 {
                let _ = socket.send_to(&probe, SocketAddr::new(ip, port)).await;
            }
            if let Ok(Ok(seen)) = tokio::time::timeout(Duration::from_secs(3), rx).await {
                *self.inner.punch.public.lock() = Some(seen);
                return Some(seen);
            }
            self.inner.punch.observing.lock().remove(&nonce);
        }
        None
    }

    /// Connections to forwarders on a direct path, with the forwarder's IP.
    fn direct_forwarders(&self) -> Vec<(Connection, IpAddr)> {
        self.inner
            .forwarders
            .read()
            .values()
            .filter_map(|c| {
                let ip =
                    c.paths()
                        .iter()
                        .find_map(|p| match (p.is_selected(), p.remote_addr()) {
                            (true, iroh::TransportAddr::Ip(a)) => Some(a.ip()),
                            _ => None,
                        })?;
                Some((c.clone(), ip))
            })
            .collect()
    }

    /// Reads one punch socket. On the easy side's shared socket `dedicated`
    /// is `None`; a hard side's attempt socket carries the peer it was
    /// opened for and the nonce it answers.
    async fn receive_loop(self, socket: Arc<UdpSocket>, dedicated: Option<(EndpointId, [u8; 16])>) {
        let mut buf = vec![0u8; 2048];
        loop {
            let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                return;
            };
            if n == 0 {
                continue;
            }
            let body = &buf[1..n];
            match buf[0] {
                TAG_DATA => {
                    let peer = self
                        .inner
                        .punch
                        .punched
                        .lock()
                        .iter()
                        .find(|(_, p)| p.remote == from && Arc::ptr_eq(&p.socket, &socket))
                        .map(|(id, _)| *id);
                    if let Some(peer) = peer {
                        PathStats::add(&self.inner.stats.received);
                        let packet = bytes::Bytes::copy_from_slice(body);
                        if self
                            .inner
                            .inbox_tx
                            .read()
                            .try_send((punched_addr(peer), packet))
                            .is_err()
                        {
                            PathStats::add(&self.inner.stats.dropped);
                        }
                    }
                }
                TAG_PROBE => {
                    // Hard side: a probe that found this socket's mapping.
                    if let Some((peer, nonce)) = dedicated
                        && body == nonce
                    {
                        let mut ack = vec![TAG_ACK];
                        ack.extend_from_slice(&nonce);
                        let _ = socket.send_to(&ack, from).await;
                        self.adopt_punched(peer, socket.clone(), from);
                    }
                }
                TAG_ACK => {
                    // Easy side: the hard side answered a probe.
                    let attempt = *self.inner.punch.easy_attempt.lock();
                    if dedicated.is_none()
                        && let Some((nonce, peer, ip)) = attempt
                        && body == nonce
                        && from.ip() == ip
                    {
                        self.adopt_punched(peer, socket.clone(), from);
                    }
                }
                TAG_OBSERVED if body.len() > 16 => {
                    let nonce: [u8; 16] = body[..16].try_into().unwrap_or_default();
                    let seen = std::str::from_utf8(&body[16..])
                        .ok()
                        .and_then(|s| s.parse().ok());
                    if let (Some(tx), Some(seen)) =
                        (self.inner.punch.observing.lock().remove(&nonce), seen)
                    {
                        let _ = tx.send(seen);
                    }
                }
                _ => {}
            }
        }
    }

    fn adopt_punched(&self, peer: EndpointId, socket: Arc<UdpSocket>, remote: SocketAddr) {
        let path = Arc::new(Punched { socket, remote });
        let fresh = self
            .inner
            .punch
            .punched
            .lock()
            .insert(peer, path.clone())
            .is_none();
        if fresh {
            tracing::info!(peer = %peer.fmt_short(), %remote, "punched a direct path");
            self.publish_local();
            let this = self.clone();
            tokio::spawn(async move {
                // Keeps the NAT mappings open while the path is in use, and
                // lets iroh open it on the connections to the peer.
                this.announce_punched(peer).await;
                loop {
                    tokio::time::sleep(KEEPALIVE).await;
                    let current = this.inner.punch.punched.lock().get(&peer).cloned();
                    let Some(current) = current.filter(|c| Arc::ptr_eq(c, &path)) else {
                        return;
                    };
                    let _ = current
                        .socket
                        .send_to(&[TAG_KEEPALIVE], current.remote)
                        .await;
                }
            });
        }
    }

    /// Names the punched path to iroh for `peer`, so it opens it on the
    /// connections this node has to the peer.
    async fn announce_punched(&self, peer: EndpointId) {
        let Some(endpoint) = self.inner.endpoint.read().clone() else {
            return;
        };
        let addr =
            EndpointAddr::new(peer).with_addrs([iroh::TransportAddr::Custom(punched_addr(peer))]);
        let named =
            tokio::time::timeout(Duration::from_secs(10), endpoint.connect(addr, ALPN_PUNCH)).await;
        if let Ok(Ok(conn)) = named {
            conn.close(0u32.into(), b"named");
        }
    }

    /// Whether an attempt towards `peer` may start now: this node is behind
    /// an endpoint-dependent NAT, has no punched path to it, and has not
    /// tried it within [`RETRY_AFTER`].
    pub fn punch_due(&self, peer: &EndpointId) -> bool {
        matches!(self.nat(), NatSide::Hard(_))
            && !self.inner.punch.punched.lock().contains_key(peer)
            && self
                .inner
                .punch
                .attempts
                .lock()
                .get(peer)
                .is_none_or(|at| at.elapsed() >= RETRY_AFTER)
    }

    /// As the hard side, tries to punch a direct path to `peer`. Returns
    /// whether one exists afterwards.
    pub async fn punch(&self, peer: EndpointAddr) -> bool {
        let id = peer.id;
        let NatSide::Hard(hard_ip) = self.nat() else {
            return false;
        };
        if self.inner.punch.punched.lock().contains_key(&id) {
            return true;
        }
        {
            let mut attempts = self.inner.punch.attempts.lock();
            if attempts
                .get(&id)
                .is_some_and(|at| at.elapsed() < RETRY_AFTER)
            {
                return false;
            }
            attempts.insert(id, Instant::now());
        }
        let Ok(_one) = self.inner.punch.busy.try_lock() else {
            return false;
        };
        let Some(endpoint) = self.inner.endpoint.read().clone() else {
            return false;
        };
        let nonce: [u8; 16] = rand::random();
        let Ok(Ok(conn)) =
            tokio::time::timeout(Duration::from_secs(10), endpoint.connect(peer, ALPN_PUNCH)).await
        else {
            self.inner
                .punch
                .note(format!("{}: no connection to ask", id.fmt_short()));
            return false;
        };
        let easy = match ask(&conn, &Message::Request { hard_ip, nonce }).await {
            Some(Message::Accept { easy }) => easy,
            other => {
                self.inner
                    .punch
                    .note(format!("{}: refused {other:?}", id.fmt_short()));
                return false;
            }
        };
        // Open the mappings: one socket per mapping, each sending towards
        // the easy side's address.
        let mut sockets = Vec::with_capacity(HARD_SOCKETS);
        for _ in 0..HARD_SOCKETS {
            let Ok(s) = UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).await else {
                break;
            };
            let s = Arc::new(s);
            let _ = s.send_to(&[TAG_KEEPALIVE], easy).await;
            sockets.push(s);
        }
        let loops: Vec<_> = sockets
            .iter()
            .map(|s| tokio::spawn(self.clone().receive_loop(s.clone(), Some((id, nonce)))))
            .collect();
        let deadline = Instant::now() + ATTEMPT;
        while Instant::now() < deadline && !self.inner.punch.punched.lock().contains_key(&id) {
            for s in sockets.iter().step_by(16) {
                let _ = s.send_to(&[TAG_KEEPALIVE], easy).await;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        conn.close(0u32.into(), b"done");
        // Every socket but the winner closes with its loop.
        let winner = self
            .inner
            .punch
            .punched
            .lock()
            .get(&id)
            .map(|p| p.socket.clone());
        for (s, l) in sockets.iter().zip(loops) {
            if winner.as_ref().is_none_or(|w| !Arc::ptr_eq(w, s)) {
                l.abort();
            }
        }
        self.inner.punch.note(format!(
            "{}: {} with {} sockets towards {easy}",
            id.fmt_short(),
            if winner.is_some() {
                "punched"
            } else {
                "no probe arrived"
            },
            sockets.len()
        ));
        winner.is_some()
    }

    /// As the easy side, answers a punch request from `peer`.
    async fn answer_punch(&self, peer: EndpointId, request: Message) -> Message {
        let Message::Request { hard_ip, nonce } = request else {
            return Message::Refuse("not a request".into());
        };
        if !matches!(self.nat(), NatSide::Easy) {
            return Message::Refuse("this node's NAT is not endpoint-independent".into());
        }
        if self.inner.punch.easy_attempt.lock().is_some() {
            return Message::Refuse("busy".into());
        }
        let Ok(socket) = self.punch_socket().await else {
            return Message::Refuse("no socket".into());
        };
        let Some(easy) = self.punch_public().await else {
            return Message::Refuse("no forwarder reported this node's address".into());
        };
        *self.inner.punch.easy_attempt.lock() = Some((nonce, peer, hard_ip));
        let this = self.clone();
        tokio::spawn(async move {
            // Give the hard side a moment to open its mappings, then probe
            // random ports at its IP, paced.
            tokio::time::sleep(Duration::from_millis(300)).await;
            let mut probe = vec![TAG_PROBE];
            probe.extend_from_slice(&nonce);
            for i in 0..EASY_PROBES {
                if this.inner.punch.punched.lock().contains_key(&peer) {
                    break;
                }
                let port = LOW_PORT + (rand::random::<u16>() % (u16::MAX - LOW_PORT));
                let _ = socket.send_to(&probe, SocketAddr::new(hard_ip, port)).await;
                if i % 8 == 7 {
                    tokio::time::sleep(Duration::from_millis(16)).await;
                }
            }
            tokio::time::sleep(ATTEMPT / 2).await;
            *this.inner.punch.easy_attempt.lock() = None;
        });
        Message::Accept { easy }
    }
}

async fn ask(conn: &Connection, message: &Message) -> Option<Message> {
    let (mut send, mut recv) = conn.open_bi().await.ok()?;
    send.write_all(&serde_json::to_vec(message).ok()?)
        .await
        .ok()?;
    send.finish().ok()?;
    let answer = tokio::time::timeout(Duration::from_secs(10), recv.read_to_end(4096))
        .await
        .ok()?
        .ok()?;
    serde_json::from_slice(&answer).ok()
}

/// Answers punch requests and the naming connections.
#[derive(Debug, Clone)]
pub struct PunchService {
    paths: Paths,
}

impl PunchService {
    /// The service over `paths`.
    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }
}

impl ProtocolHandler for PunchService {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let peer = conn.remote_id();
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let Ok(body) = recv.read_to_end(4096).await else {
                break;
            };
            let Ok(request) = serde_json::from_slice::<Message>(&body) else {
                break;
            };
            let answer = self.paths.answer_punch(peer, request).await;
            let _ = send
                .write_all(&serde_json::to_vec(&answer).unwrap_or_default())
                .await;
            let _ = send.finish();
        }
        // A naming connection opens no stream: being dialed with the
        // punched path named is the point. Name it back, so the paths on
        // this side's own connections to the peer open too.
        if self.paths.inner.punch.punched.lock().contains_key(&peer) {
            self.paths.announce_punched(peer).await;
        }
        Ok(())
    }
}

/// The forwarder's side of the punch address check: a UDP socket that
/// answers each observe probe with the address it came from.
#[derive(Debug)]
pub(super) struct Observer {
    port: u16,
}

impl Observer {
    pub(super) async fn spawn() -> io::Result<Self> {
        let socket = UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).await?;
        let port = socket.local_addr()?.port();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                if n == 17 && buf[0] == TAG_OBSERVE {
                    let mut answer = vec![TAG_OBSERVED];
                    answer.extend_from_slice(&buf[1..17]);
                    answer.extend_from_slice(from.to_string().as_bytes());
                    let _ = socket.send_to(&answer, from).await;
                }
            }
        });
        Ok(Self { port })
    }

    pub(super) fn port(&self) -> u16 {
        self.port
    }
}

/// The observe port a forwarder announces on a stream of the connection.
async fn observe_port(conn: &Connection) -> Option<u16> {
    let (mut send, mut recv) = conn.open_bi().await.ok()?;
    send.write_all(b"observe").await.ok()?;
    send.finish().ok()?;
    let answer = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(16))
        .await
        .ok()?
        .ok()?;
    std::str::from_utf8(&answer).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_punched_address_round_trips() {
        let id = iroh::SecretKey::from_bytes(&[4; 32]).public();
        assert_eq!(parse_punched_addr(&punched_addr(id)), Some(id));
        assert_eq!(
            parse_punched_addr(&super::super::peer_relay_addr(id, id)),
            None
        );
    }

    #[test]
    fn the_birthday_odds_are_high_and_the_work_bounded() {
        // P(no probe hits one of HARD_SOCKETS mappings among the NAT's ports).
        let ports = f64::from(u16::MAX - LOW_PORT);
        let miss = (1.0 - HARD_SOCKETS as f64 / ports).powi(EASY_PROBES as i32);
        assert!(1.0 - miss > 0.97, "success {}", 1.0 - miss);
        const { assert!(HARD_SOCKETS <= 256 && EASY_PROBES <= 1_024) };
    }
}
