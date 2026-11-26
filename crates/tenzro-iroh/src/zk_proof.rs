//! Zero-knowledge proofs sent to validators directly.
//!
//! A proof envelope is larger than a block or a gossip message can carry,
//! so a prover sends it to validators over [`ALPN_ZK_PROOF`]. A validator
//! runs the verifier on it and, when it verifies, states its verdict on
//! chain; the proof is recorded once two thirds of the bonded stake stated
//! it. The protocol is open to anyone: each request is one envelope of at
//! most [`MAX_PROOF_BYTES`], and a remote is answered at most once per
//! [`PROOF_INTERVAL`], so verifying costs a validator what it chooses.
//!
//! Request: `len: u32 BE` then the envelope. Reply: `0x00` taken, `0x01`
//! then `len: u32 BE` and the reason it was refused (UTF-8, at most
//! [`MAX_REASON_BYTES`]), or `0x02` asked again too soon.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use parking_lot::{Mutex, RwLock};
use tracing::{debug, trace};

use crate::error::{IrohError, IrohResult};

/// ALPN of the protocol.
pub const ALPN_ZK_PROOF: &[u8] = b"tenzro/zk-proof";

/// Largest envelope a request carries: the largest a proof may be.
pub const MAX_PROOF_BYTES: usize = 4 << 20;

/// Longest refusal reason a reply carries.
pub const MAX_REASON_BYTES: usize = 1_024;

/// How often one remote is answered.
pub const PROOF_INTERVAL: Duration = Duration::from_secs(30);

/// Most remotes whose last answer is remembered; past it a new remote waits
/// for the oldest to age out.
const MAX_PACED_REMOTES: usize = 4_096;

/// What a validator does with a proof it was sent.
#[async_trait]
pub trait ProofSink: Send + Sync {
    /// Takes `envelope`, or says why it does not.
    async fn offer(&self, envelope: Vec<u8>) -> Result<(), String>;
}

/// A sink set once the node has what it needs to verify and state verdicts;
/// until then every proof is refused.
#[derive(Default)]
pub struct DeferredProofSink {
    inner: RwLock<Option<Arc<dyn ProofSink>>>,
}

impl DeferredProofSink {
    /// Installs `sink`.
    pub fn set(&self, sink: Arc<dyn ProofSink>) {
        *self.inner.write() = Some(sink);
    }
}

#[async_trait]
impl ProofSink for DeferredProofSink {
    async fn offer(&self, envelope: Vec<u8>) -> Result<(), String> {
        let sink = self.inner.read().clone();
        match sink {
            Some(s) => s.offer(envelope).await,
            None => Err("this node takes no proofs".to_string()),
        }
    }
}

/// When each remote was last answered.
#[derive(Default)]
struct Pacing {
    last: HashMap<EndpointId, Instant>,
}

impl Pacing {
    /// Whether `remote` may be answered at `now`, remembering it if so.
    fn admit(&mut self, remote: EndpointId, now: Instant) -> bool {
        if let Some(at) = self.last.get(&remote)
            && now.duration_since(*at) < PROOF_INTERVAL
        {
            return false;
        }
        if !self.last.contains_key(&remote) && self.last.len() >= MAX_PACED_REMOTES {
            self.last
                .retain(|_, at| now.duration_since(*at) < PROOF_INTERVAL);
            if self.last.len() >= MAX_PACED_REMOTES {
                return false;
            }
        }
        self.last.insert(remote, now);
        true
    }
}

/// The handler of [`ALPN_ZK_PROOF`].
pub struct ZkProofProtocol {
    sink: Arc<dyn ProofSink>,
    pacing: Mutex<Pacing>,
}

impl ZkProofProtocol {
    /// A handler handing proofs to `sink`.
    pub fn new(sink: Arc<dyn ProofSink>) -> Self {
        Self {
            sink,
            pacing: Mutex::new(Pacing::default()),
        }
    }
}

impl std::fmt::Debug for ZkProofProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZkProofProtocol").finish_non_exhaustive()
    }
}

impl ProtocolHandler for ZkProofProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let remote = conn.remote_id();
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            Err(e) => {
                trace!(target: "tenzro_iroh::zk_proof", %remote, error = %e, "zk-proof connection closed");
                return Ok(());
            }
        };
        let mut len = [0u8; 4];
        if recv.read_exact(&mut len).await.is_err() {
            return Ok(());
        }
        let len = u32::from_be_bytes(len) as usize;
        let reply = if len > MAX_PROOF_BYTES {
            refusal(&format!(
                "a proof envelope is at most {MAX_PROOF_BYTES} bytes; this one is {len}"
            ))
        } else if !self.pacing.lock().admit(remote, Instant::now()) {
            vec![2u8]
        } else {
            let mut envelope = vec![0u8; len];
            if recv.read_exact(&mut envelope).await.is_err() {
                return Ok(());
            }
            match self.sink.offer(envelope).await {
                Ok(()) => vec![0u8],
                Err(why) => refusal(&why),
            }
        };
        debug!(target: "tenzro_iroh::zk_proof", %remote, len, answer = reply[0], "answered a proof");
        if send.write_all(&reply).await.is_err() || send.finish().is_err() {
            return Ok(());
        }
        conn.closed().await;
        Ok(())
    }
}

fn refusal(why: &str) -> Vec<u8> {
    let mut why = why.as_bytes();
    if why.len() > MAX_REASON_BYTES {
        why = &why[..MAX_REASON_BYTES];
    }
    let mut out = Vec::with_capacity(5 + why.len());
    out.push(1u8);
    out.extend_from_slice(&(why.len() as u32).to_be_bytes());
    out.extend_from_slice(why);
    out
}

/// Sends `envelope` to `peer`: `Ok(Ok(()))` when it took it, `Ok(Err(why))`
/// when it refused it.
pub async fn send_proof(
    endpoint: &Endpoint,
    peer: impl Into<EndpointAddr>,
    envelope: &[u8],
) -> IrohResult<Result<(), String>> {
    if envelope.len() > MAX_PROOF_BYTES {
        return Err(IrohError::Backend(format!(
            "a proof envelope is at most {MAX_PROOF_BYTES} bytes; this one is {}",
            envelope.len()
        )));
    }
    let conn =
        crate::bounded::connect(endpoint, peer, ALPN_ZK_PROOF, crate::bounded::BACKSTOP).await?;
    let (mut send, mut recv) = crate::bounded::open_bi(&conn, crate::bounded::BACKSTOP).await?;
    send.write_all(&(envelope.len() as u32).to_be_bytes())
        .await
        .map_err(|e| IrohError::Backend(format!("zk-proof write: {e}")))?;
    send.write_all(envelope)
        .await
        .map_err(|e| IrohError::Backend(format!("zk-proof write: {e}")))?;
    send.finish()
        .map_err(|e| IrohError::Backend(format!("zk-proof finish: {e}")))?;
    let mut tag = [0u8; 1];
    recv.read_exact(&mut tag)
        .await
        .map_err(|e| IrohError::Backend(format!("zk-proof read: {e}")))?;
    let answer = match tag[0] {
        0 => Ok(Ok(())),
        1 => {
            let mut len = [0u8; 4];
            recv.read_exact(&mut len)
                .await
                .map_err(|e| IrohError::Backend(format!("zk-proof read: {e}")))?;
            let len = u32::from_be_bytes(len) as usize;
            if len > MAX_REASON_BYTES {
                return Err(IrohError::Backend(format!(
                    "zk-proof refusal of {len} bytes"
                )));
            }
            let mut why = vec![0u8; len];
            recv.read_exact(&mut why)
                .await
                .map_err(|e| IrohError::Backend(format!("zk-proof read: {e}")))?;
            Ok(Err(String::from_utf8_lossy(&why).into_owned()))
        }
        2 => Err(IrohError::Backend(format!(
            "zk-proof: asked again too soon; one proof per {}s",
            PROOF_INTERVAL.as_secs()
        ))),
        t => Err(IrohError::Backend(format!("zk-proof: unknown answer {t}"))),
    };
    conn.close(0u32.into(), b"done");
    answer
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::protocol::Router;

    struct Takes;

    #[async_trait]
    impl ProofSink for Takes {
        async fn offer(&self, envelope: Vec<u8>) -> Result<(), String> {
            if envelope.starts_with(b"good") {
                Ok(())
            } else {
                Err("it does not verify".to_string())
            }
        }
    }

    async fn endpoint() -> Endpoint {
        Endpoint::bind(iroh::endpoint::presets::Minimal)
            .await
            .unwrap()
    }

    fn remote(i: u32) -> EndpointId {
        let mut bytes = [1u8; 32];
        bytes[..4].copy_from_slice(&i.to_be_bytes());
        iroh::SecretKey::from_bytes(&bytes).public()
    }

    /// A proof is taken or refused with its reason; one remote asking again
    /// at once is told it is too soon while another is answered; an envelope
    /// past the bound is refused unread; a node with no sink refuses.
    #[tokio::test]
    async fn proofs_are_answered_once_per_interval_per_remote() {
        let server = endpoint().await;
        let router = Router::builder(server.clone())
            .accept(ALPN_ZK_PROOF, ZkProofProtocol::new(Arc::new(Takes)))
            .spawn();
        let addr = server.addr();
        let (a, b, c) = (endpoint().await, endpoint().await, endpoint().await);

        assert_eq!(
            send_proof(&a, addr.clone(), b"good proof").await.unwrap(),
            Ok(())
        );
        let too_soon = send_proof(&a, addr.clone(), b"good proof")
            .await
            .unwrap_err();
        assert!(too_soon.to_string().contains("too soon"), "{too_soon}");
        assert_eq!(
            send_proof(&b, addr.clone(), b"bad proof").await.unwrap(),
            Err("it does not verify".to_string())
        );
        assert!(
            send_proof(&c, addr.clone(), &vec![0u8; MAX_PROOF_BYTES + 1])
                .await
                .is_err()
        );
        router.shutdown().await.unwrap();

        let deferred = endpoint().await;
        let router = Router::builder(deferred.clone())
            .accept(
                ALPN_ZK_PROOF,
                ZkProofProtocol::new(Arc::new(DeferredProofSink::default())),
            )
            .spawn();
        assert!(
            send_proof(&c, deferred.addr(), b"good proof")
                .await
                .unwrap()
                .is_err()
        );
        router.shutdown().await.unwrap();
    }

    #[test]
    fn pacing_answers_a_remote_once_per_interval_and_bounds_its_table() {
        let mut pacing = Pacing::default();
        let now = Instant::now();
        let one = remote(0);
        assert!(pacing.admit(one, now));
        assert!(!pacing.admit(one, now + Duration::from_secs(1)));
        assert!(pacing.admit(one, now + PROOF_INTERVAL));
        for i in 1..=MAX_PACED_REMOTES as u32 {
            pacing.admit(remote(i), now + PROOF_INTERVAL);
        }
        assert!(pacing.last.len() <= MAX_PACED_REMOTES);
        let late = remote(u32::MAX);
        assert!(
            !pacing.admit(late, now + PROOF_INTERVAL),
            "a full table admits no newcomer"
        );
        assert!(
            pacing.admit(late, now + PROOF_INTERVAL * 3),
            "once the table ages out it does"
        );
    }
}
