//! `tenzro/consensus` ALPN — the stream validators exchange consensus
//! frames over.
//!
//! This module is transport only. The connection is authenticated to the
//! peer's iroh key by QUIC, but consensus does not trust that key: the first
//! frames on the stream are a handshake both validators sign with their
//! hardware consensus keys, and every later frame carries a MAC under keys
//! derived from it (see `tenzro_consensus::channel`). Frames are
//! length-prefixed:
//!
//! ```text
//! frame := len:u32 (big-endian) || bytes[len]
//! ```

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr};
use parking_lot::RwLock;
use tracing::{debug, trace};

use crate::error::{IrohError, IrohResult};

/// ALPN for validator consensus channels.
pub const ALPN_CONSENSUS: &[u8] = b"tenzro/consensus";

/// Serves consensus streams a peer opened.
#[async_trait]
pub trait ConsensusStreamHandler: Send + Sync + fmt::Debug + 'static {
    /// Whether a connection from `remote` (its iroh endpoint key) is
    /// admitted at all. Asked before any stream of the connection is
    /// accepted; a refused connection is closed at once.
    fn admits(&self, remote: &[u8; 32]) -> bool;

    /// Takes over one bidirectional stream opened by `remote` (its iroh
    /// endpoint key). `rtt` is the connection's current round-trip estimate
    /// on its selected path, for sizing budgets that must stretch with the
    /// path rather than assume a LAN (see `tenzro_node`'s handshake and
    /// channel-silence budgets).
    async fn accept_stream(
        &self,
        remote: [u8; 32],
        rtt: std::time::Duration,
        send: SendStream,
        recv: RecvStream,
    );
}

/// A handler installed once the node's consensus is running. Until then
/// streams are closed at once.
#[derive(Debug, Clone, Default)]
pub struct DeferredConsensusHandler {
    inner: Arc<RwLock<Option<Arc<dyn ConsensusStreamHandler>>>>,
}

impl DeferredConsensusHandler {
    /// An unbound handler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs the backing handler.
    pub fn set(&self, handler: Arc<dyn ConsensusStreamHandler>) {
        *self.inner.write() = Some(handler);
    }
}

#[async_trait]
impl ConsensusStreamHandler for DeferredConsensusHandler {
    fn admits(&self, remote: &[u8; 32]) -> bool {
        self.inner.read().as_ref().is_some_and(|h| h.admits(remote))
    }

    async fn accept_stream(
        &self,
        remote: [u8; 32],
        rtt: std::time::Duration,
        send: SendStream,
        recv: RecvStream,
    ) {
        let backing = self.inner.read().clone();
        if let Some(h) = backing {
            h.accept_stream(remote, rtt, send, recv).await;
        }
    }
}

/// Protocol handler serving [`ALPN_CONSENSUS`].
#[derive(Debug, Clone)]
pub struct ConsensusProtocol {
    handler: Arc<dyn ConsensusStreamHandler>,
}

impl ConsensusProtocol {
    /// A handler passing streams to `handler`.
    pub fn new(handler: Arc<dyn ConsensusStreamHandler>) -> Self {
        Self { handler }
    }
}

impl ProtocolHandler for ConsensusProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let remote = *conn.remote_id().as_bytes();
        if !self.handler.admits(&remote) {
            debug!(target: "tenzro_iroh::consensus", remote = %hex::encode(&remote[..8]), "consensus connection refused");
            conn.close(0u32.into(), b"not admitted");
            return Ok(());
        }
        loop {
            let (send, recv) = match conn.accept_bi().await {
                Ok(pair) => pair,
                Err(e) => {
                    trace!(target: "tenzro_iroh::consensus", error = %e, "consensus connection closed");
                    return Ok(());
                }
            };
            debug!(target: "tenzro_iroh::consensus", remote = %hex::encode(&remote[..8]), "consensus stream opened");
            let rtt = conn
                .paths()
                .iter()
                .find(|p| p.is_selected())
                .map(|p| p.rtt())
                .unwrap_or_default();
            let handler = self.handler.clone();
            tokio::spawn(async move { handler.accept_stream(remote, rtt, send, recv).await });
        }
    }
}

/// Opens a consensus stream to `peer` (an endpoint id, resolved through the
/// endpoint's discovery, or a full address), keeping the connection so a
/// caller can read its rtt estimate off it (`Connection::paths`) to size
/// budgets that must stretch with the path.
pub async fn open_consensus_connection(
    endpoint: &Endpoint,
    peer: impl Into<EndpointAddr>,
) -> IrohResult<(Connection, SendStream, RecvStream)> {
    let peer: EndpointAddr = peer.into();
    let id = peer.id;
    let conn = endpoint
        .connect(peer, ALPN_CONSENSUS)
        .await
        .map_err(|e| IrohError::Backend(format!("consensus connect to {id}: {e} ({e:?})")))?;
    let (send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| IrohError::Backend(format!("consensus open stream: {e} ({e:?})")))?;
    Ok((conn, send, recv))
}

/// Opens a consensus stream to `peer`, discarding the connection: for a
/// caller with no use for its rtt (see `open_consensus_connection`).
pub async fn open_consensus_stream(
    endpoint: &Endpoint,
    peer: impl Into<EndpointAddr>,
) -> IrohResult<(SendStream, RecvStream)> {
    let (_conn, send, recv) = open_consensus_connection(endpoint, peer).await?;
    Ok((send, recv))
}

/// Writes one length-prefixed frame.
pub async fn write_frame(send: &mut SendStream, bytes: &[u8]) -> IrohResult<()> {
    let len =
        u32::try_from(bytes.len()).map_err(|_| IrohError::Backend("frame too large".into()))?;
    send.write_all(&len.to_be_bytes())
        .await
        .map_err(|e| IrohError::Backend(format!("consensus write: {e} ({e:?})")))?;
    send.write_all(bytes)
        .await
        .map_err(|e| IrohError::Backend(format!("consensus write: {e} ({e:?})")))
}

/// Reads one length-prefixed frame of at most `max` bytes. The length is
/// checked before anything is read, and the frame's buffer grows only as its
/// bytes arrive.
pub async fn read_frame<R>(recv: &mut R, max: usize) -> IrohResult<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin + ?Sized,
{
    use tokio::io::AsyncReadExt;
    let mut len = [0u8; 4];
    recv.read_exact(&mut len)
        .await
        .map_err(|e| IrohError::Backend(format!("consensus read: {e} ({e:?})")))?;
    let len = u32::from_be_bytes(len) as usize;
    if len > max {
        return Err(IrohError::Backend(format!(
            "consensus frame of {len} bytes exceeds {max}"
        )));
    }
    crate::request::read_body(recv, len)
        .await
        .map_err(|e| IrohError::Backend(format!("consensus read: {e} ({e:?})")))
}

/// Reads one length-prefixed frame of at most `max` bytes, failing only if
/// no bytes arrive for `idle` at any single point, rather than if the frame
/// as a whole takes longer than that to arrive.
///
/// [`read_frame`] wraps one `read_exact` around the length and another
/// around the whole body, so a caller that bounds it with one outer timeout
/// is really bounding how long the *entire* frame takes to arrive. Under
/// packet loss that is the wrong thing to bound: a large frame can
/// legitimately take several multiples of one round trip to arrive in full
/// once retransmission is counted, while still being delivered steadily the
/// whole time. What actually distinguishes a peer that is still sending,
/// slowly, from one that has gone silent is whether *any* new byte has
/// shown up recently -- not whether the *whole* frame has. Seen directly in
/// chaos seed 3054677367 under a 206s, 10%-loss netem window: 44 "channel
/// is down" events and 25 "inbound channel closed" events in 3.5 minutes,
/// every one of them this exact `read_frame` call timing out mid-transfer
/// of a frame that was still arriving (TENZRO-INFLIGHT.md, 2026-10-21,
/// `LIVENESS-3054677367-2026-10-21.md`).
pub async fn read_frame_idle<R>(
    recv: &mut R,
    max: usize,
    idle: std::time::Duration,
) -> IrohResult<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin + ?Sized,
{
    use tokio::io::AsyncReadExt;

    async fn read_some<R: tokio::io::AsyncRead + Unpin + ?Sized>(
        recv: &mut R,
        buf: &mut [u8],
        idle: std::time::Duration,
    ) -> IrohResult<usize> {
        let n = tokio::time::timeout(idle, recv.read(buf))
            .await
            .map_err(|_| {
                IrohError::Backend(format!(
                    "consensus read: nothing arrived from the peer for {}s: the channel failed in one direction",
                    idle.as_secs()
                ))
            })?
            .map_err(|e| IrohError::Backend(format!("consensus read: {e} ({e:?})")))?;
        if n == 0 {
            return Err(IrohError::Backend(
                "consensus read: the peer closed its send side".into(),
            ));
        }
        Ok(n)
    }

    let mut len_bytes = [0u8; 4];
    let mut filled = 0usize;
    while filled < len_bytes.len() {
        filled += read_some(recv, &mut len_bytes[filled..], idle).await?;
    }
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > max {
        return Err(IrohError::Backend(format!(
            "consensus frame of {len} bytes exceeds {max}"
        )));
    }
    let mut body = vec![0u8; len];
    let mut filled = 0usize;
    while filled < len {
        filled += read_some(recv, &mut body[filled..], idle).await?;
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::mpsc;

    /// A frame that arrives in small, separated pieces -- as a large frame
    /// does under packet loss, not because anything is wrong with the
    /// sender -- must not be torn down as if the peer had gone silent, the
    /// way wrapping [`read_frame`] in one outer timeout used to (seen
    /// directly in chaos seed 3054677367's netem window: 44 "channel is
    /// down" events in 3.5 minutes, every one of them this read timing out
    /// mid-transfer). [`read_frame_idle`] must keep reading as long as each
    /// gap between pieces stays under its idle bound, even though the
    /// pieces together take much longer than that bound to finish arriving.
    #[tokio::test(start_paused = true)]
    async fn a_frame_arriving_in_slow_pieces_is_not_mistaken_for_silence() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let body = vec![7u8; 300];
        let idle = Duration::from_millis(500);
        let pieces: Vec<Vec<u8>> = body.chunks(50).map(|c| c.to_vec()).collect();
        let sender = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            client
                .write_all(&(300u32).to_be_bytes())
                .await
                .expect("length prefix");
            for piece in pieces {
                // Each gap is comfortably under `idle`, but there are enough
                // of them that the whole transfer takes well over it -- the
                // exact shape of a large frame trickling in under loss.
                tokio::time::sleep(Duration::from_millis(300)).await;
                client.write_all(&piece).await.expect("piece");
            }
        });
        let got = tokio::time::timeout(
            Duration::from_secs(10),
            read_frame_idle(&mut server, 1 << 20, idle),
        )
        .await
        .expect("read_frame_idle should not itself hang")
        .expect("a frame arriving slowly but steadily must still be read");
        assert_eq!(got, body);
        sender.await.expect("sender task");
    }

    /// The other side of the same fix: a peer that truly has gone silent --
    /// no bytes at all for longer than the idle bound -- must still be
    /// detected and reported, not waited on forever.
    #[tokio::test(start_paused = true)]
    async fn a_peer_that_truly_goes_silent_is_still_caught() {
        let (client, mut server) = tokio::io::duplex(4096);
        // Held, never written to and never dropped: the length prefix never
        // arrives, and the connection never closes out from under the read.
        let _held = client;
        let idle = Duration::from_millis(200);
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            read_frame_idle(&mut server, 1 << 20, idle),
        )
        .await
        .expect("read_frame_idle must give up on its own, not hang until the outer timeout");
        assert!(
            result.is_err(),
            "a peer sending nothing at all must still be reported as failed"
        );
    }

    #[derive(Debug)]
    struct Echo(mpsc::UnboundedSender<Vec<u8>>, Option<[u8; 32]>);

    #[async_trait]
    impl ConsensusStreamHandler for Echo {
        fn admits(&self, remote: &[u8; 32]) -> bool {
            self.1.is_none_or(|only| &only == remote)
        }

        async fn accept_stream(
            &self,
            _remote: [u8; 32],
            _rtt: Duration,
            mut send: SendStream,
            mut recv: RecvStream,
        ) {
            while let Ok(f) = read_frame(&mut recv, 1 << 20).await {
                let _ = self.0.send(f.clone());
                if write_frame(&mut send, &f).await.is_err() {
                    return;
                }
            }
        }
    }

    #[tokio::test]
    async fn frames_cross_the_alpn_and_oversized_ones_are_refused() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let deferred = DeferredConsensusHandler::new();
        let server = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .unwrap();
        let _router = iroh::protocol::Router::builder(server.clone())
            .accept(
                ALPN_CONSENSUS,
                ConsensusProtocol::new(Arc::new(deferred.clone())),
            )
            .spawn();
        deferred.set(Arc::new(Echo(tx, None)));
        let client = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .unwrap();
        let (mut send, mut recv) = open_consensus_stream(&client, server.addr()).await.unwrap();
        write_frame(&mut send, b"hello").await.unwrap();
        assert_eq!(read_frame(&mut recv, 64).await.unwrap(), b"hello");
        assert_eq!(rx.recv().await.unwrap(), b"hello");
        write_frame(&mut send, &[7u8; 100]).await.unwrap();
        assert!(
            read_frame(&mut recv, 64).await.is_err(),
            "reply larger than the reader's bound"
        );
    }

    #[tokio::test]
    async fn a_connection_the_handler_does_not_admit_is_closed_before_any_stream() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let server = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .unwrap();
        let member = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .unwrap();
        let outsider = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .unwrap();
        let _router = iroh::protocol::Router::builder(server.clone())
            .accept(
                ALPN_CONSENSUS,
                ConsensusProtocol::new(Arc::new(Echo(tx, Some(*member.id().as_bytes())))),
            )
            .spawn();
        let refused = async {
            let (mut send, mut recv) = open_consensus_stream(&outsider, server.addr()).await?;
            write_frame(&mut send, b"let me in").await?;
            read_frame(&mut recv, 64).await
        };
        assert!(refused.await.is_err(), "an outsider got a stream");
        let (mut send, mut recv) = open_consensus_stream(&member, server.addr()).await.unwrap();
        write_frame(&mut send, b"member").await.unwrap();
        assert_eq!(read_frame(&mut recv, 64).await.unwrap(), b"member");
        assert_eq!(
            rx.recv().await.unwrap(),
            b"member",
            "only the member's frame reached the handler"
        );
    }
}
