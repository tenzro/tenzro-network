//! Request protocol: one request frame in, a status and a streamed body out.
//!
//! The node-to-node services that answer a single request (inference, the
//! committee data-availability store, database replication) share this one
//! wire shape, each under its own ALPN on the node's endpoint. Every request
//! rides its own bidirectional QUIC stream:
//!
//! ```text
//!   client -> server:  u32_LE(len) || request bytes, then FIN
//!   server -> client:  u16_LE(status) || body bytes ..., then FIN
//! ```
//!
//! The body is streamed as the handler produces it, so a reply can be a
//! server-sent event stream as well as a single encoded value. A handler that
//! fails part way through resets the stream, which the client reads as an
//! error rather than a truncated success. The handler is told the remote
//! `EndpointId`, which the transport has already authenticated, so it can
//! decide who it serves.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use iroh::{
    Endpoint, EndpointAddr, EndpointId,
    endpoint::{Connection, RecvStream, SendStream},
    protocol::{AcceptError, ProtocolHandler},
};
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::error::{IrohError, IrohResult};
use crate::limits::{Admission, AdmissionLimits};

/// ALPN for inference requests: a `tenzro_chat` JSON-RPC frame or an
/// OpenAI-shaped chat completion, answered with the provider's status and
/// body (streamed for `stream: true`).
pub const ALPN_INFER: &[u8] = b"tenzro/infer";

/// ALPN for committee data-availability requests (store, fetch and
/// challenge a sliver) between validators.
pub const ALPN_DA_COMMITTEE: &[u8] = b"tenzro/da-committee";

/// ALPN on which a node that serves delegated agents answers for the key it
/// holds for one agent: the public half and the node's certification of it.
pub const ALPN_AGENT_KEY: &[u8] = b"tenzro/agent-key";

/// ALPN on which a serving node receives the tokens bound to its key for
/// an agent it serves.
pub const ALPN_AGENT_TOKEN: &[u8] = b"tenzro/agent-token";

/// ALPN on which a node designated as an inference session's successor
/// accepts its assignment and the session's sealed KV-cache deltas.
pub const ALPN_KV_CHECKPOINT: &[u8] = b"tenzro/kv-checkpoint";

/// Upper bound on a KV-checkpoint request: one sealed KV-cache delta. The
/// serving node exports often enough that a delta stays well below it.
pub const MAX_KV_CHECKPOINT_REQUEST: usize = 64 * 1024 * 1024;

/// Upper bound on a registration request: a signed identity registration
/// carrying a TPM attestation, plus an owner approval.
pub const MAX_ONBOARD_REQUEST: usize = 256 * 1024;

/// Upper bound on an agent-key request.
pub const MAX_AGENT_KEY_REQUEST: usize = 4 * 1024;

/// Largest inference request, and largest inference reply read whole.
pub const MAX_INFER_BYTES: usize = 4 * 1024 * 1024;

/// Largest request a committee DA or database replication exchange accepts:
/// a primary and secondary sliver pair for a large blob, or a large write.
pub const MAX_STORE_REQUEST: usize = 16 * 1024 * 1024;

/// Status a handler that has not been installed yet answers with.
pub const STATUS_UNAVAILABLE: u16 = 503;

/// Stream reset code for a reply that failed after its status was sent.
const RESET_REPLY_FAILED: u32 = 1;

/// Largest chunk read from a reply stream at once.
const READ_CHUNK: usize = 64 * 1024;

/// The body of a [`Reply`].
pub enum ReplyBody {
    /// The whole body, already encoded.
    Full(Bytes),
    /// Body chunks as the handler produces them. An `Err` resets the stream.
    Streamed(mpsc::Receiver<Result<Bytes, String>>),
}

impl fmt::Debug for ReplyBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full(b) => write!(f, "Full({} bytes)", b.len()),
            Self::Streamed(_) => f.write_str("Streamed"),
        }
    }
}

/// A handler's answer: a status (HTTP semantics) and a body.
#[derive(Debug)]
pub struct Reply {
    /// Status code, read with HTTP semantics (200 success, 402 payment
    /// required, 503 unavailable, and so on).
    pub status: u16,
    /// The reply body.
    pub body: ReplyBody,
}

impl Reply {
    /// A reply whose whole body is at hand.
    pub fn full(status: u16, body: impl Into<Bytes>) -> Self {
        Self {
            status,
            body: ReplyBody::Full(body.into()),
        }
    }

    /// A reply whose body arrives on `chunks`.
    pub fn streamed(status: u16, chunks: mpsc::Receiver<Result<Bytes, String>>) -> Self {
        Self {
            status,
            body: ReplyBody::Streamed(chunks),
        }
    }
}

/// Serves requests arriving on one ALPN.
#[async_trait]
pub trait RequestHandler: Send + Sync + fmt::Debug + 'static {
    /// Answer `request` from the transport-authenticated peer `remote`.
    async fn handle(&self, remote: EndpointId, request: Bytes) -> Reply;
}

/// A handler that can be installed after the endpoint's router is spawned.
///
/// The router fixes its ALPNs when it starts, while the services behind them
/// come up later in node startup. Until [`Self::set`] runs, requests are
/// answered with [`STATUS_UNAVAILABLE`].
#[derive(Debug, Clone)]
pub struct DeferredRequestHandler {
    inner: Arc<RwLock<Option<Arc<dyn RequestHandler>>>>,
    label: &'static str,
}

impl DeferredRequestHandler {
    /// An empty handler; `label` names the service in the unavailable reply.
    pub fn new(label: &'static str) -> Self {
        Self {
            inner: Arc::new(RwLock::new(None)),
            label,
        }
    }

    /// Install the handler that serves from now on.
    pub fn set(&self, handler: Arc<dyn RequestHandler>) {
        *self.inner.write() = Some(handler);
    }

    /// Whether a handler is installed.
    pub fn is_ready(&self) -> bool {
        self.inner.read().is_some()
    }
}

#[async_trait]
impl RequestHandler for DeferredRequestHandler {
    async fn handle(&self, remote: EndpointId, request: Bytes) -> Reply {
        let installed = self.inner.read().clone();
        match installed {
            Some(h) => h.handle(remote, request).await,
            None => Reply::full(
                STATUS_UNAVAILABLE,
                format!("{} service is not running on this node", self.label),
            ),
        }
    }
}

/// `iroh` protocol adapter serving one ALPN with a [`RequestHandler`].
#[derive(Debug, Clone)]
pub struct RequestProtocol {
    handler: Arc<dyn RequestHandler>,
    max_request: usize,
    label: &'static str,
    admission: Admission<EndpointId>,
}

impl RequestProtocol {
    /// Serve `handler`, refusing requests larger than `max_request` bytes and
    /// streams beyond `limits`.
    pub fn new(
        label: &'static str,
        handler: Arc<dyn RequestHandler>,
        max_request: usize,
        limits: AdmissionLimits,
    ) -> Self {
        Self {
            handler,
            max_request,
            label,
            admission: Admission::new(limits),
        }
    }
}

impl ProtocolHandler for RequestProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let remote = conn.remote_id();
        debug!(target: "tenzro_iroh::request", alpn = self.label, %remote, "accepted connection");
        while let Ok((send, recv)) = conn.accept_bi().await {
            let Some(permit) = self.admission.try_admit(remote) else {
                debug!(target: "tenzro_iroh::request", alpn = self.label, %remote, "stream refused: at capacity");
                crate::limits::refuse(send, recv);
                continue;
            };
            let handler = self.handler.clone();
            let max = self.max_request;
            let label = self.label;
            let limits = *self.admission.limits();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = serve_stream(remote, send, recv, handler, max, limits).await {
                    warn!(target: "tenzro_iroh::request", alpn = label, %remote, error = %e, "request failed");
                }
            });
        }
        Ok(())
    }
}

async fn serve_stream(
    remote: EndpointId,
    mut send: SendStream,
    mut recv: RecvStream,
    handler: Arc<dyn RequestHandler>,
    max_request: usize,
    limits: AdmissionLimits,
) -> IrohResult<()> {
    let read = crate::limits::within(
        limits.read_timeout,
        "receiving the request",
        read_request(&mut recv, max_request),
    )
    .await;
    let request = match read {
        Ok(request) => request,
        Err(e) => {
            crate::limits::cut_off(&mut send, &mut recv);
            return Err(e);
        }
    };

    let reply = handler.handle(remote, Bytes::from(request)).await;
    write(&mut send, &reply.status.to_le_bytes(), &limits).await?;
    match reply.body {
        ReplyBody::Full(body) => write(&mut send, &body, &limits).await?,
        ReplyBody::Streamed(mut chunks) => {
            while let Some(chunk) = chunks.recv().await {
                match chunk {
                    Ok(bytes) => write(&mut send, &bytes, &limits).await?,
                    Err(e) => {
                        let _ = send.reset(RESET_REPLY_FAILED.into());
                        return Err(IrohError::Backend(format!("reply body: {e}")));
                    }
                }
            }
        }
    }
    send.finish()
        .map_err(|e| IrohError::Backend(format!("finish reply: {e}")))?;
    Ok(())
}

/// Reads one request: a little-endian `u32` length, then that many bytes. A
/// length above `max` is refused before anything is read.
pub async fn read_request<R>(recv: &mut R, max: usize) -> IrohResult<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin + ?Sized,
{
    use tokio::io::AsyncReadExt;
    let mut len = [0u8; 4];
    recv.read_exact(&mut len)
        .await
        .map_err(|e| IrohError::Backend(format!("read request length: {e}")))?;
    let len = u32::from_le_bytes(len) as usize;
    if len > max {
        return Err(IrohError::Backend(format!(
            "request of {len} bytes exceeds {max}"
        )));
    }
    read_body(recv, len)
        .await
        .map_err(|e| IrohError::Backend(format!("read request: {e}")))
}

/// Reads exactly `len` bytes. The buffer grows as the bytes arrive instead of
/// being reserved from the length a peer announced, so an announced body the
/// peer never sends costs no memory.
pub async fn read_body<R>(recv: &mut R, len: usize) -> std::io::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin + ?Sized,
{
    use tokio::io::AsyncReadExt;
    let mut body = Vec::with_capacity(len.min(READ_CHUNK));
    let read = (&mut *recv).take(len as u64).read_to_end(&mut body).await?;
    if read != len {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    Ok(body)
}

/// Write part of a reply, cutting the stream off when the peer does not take
/// it within the write timeout.
async fn write(send: &mut SendStream, bytes: &[u8], limits: &AdmissionLimits) -> IrohResult<()> {
    let written = crate::limits::within(limits.write_timeout, "sending the reply", async {
        send.write_all(bytes)
            .await
            .map_err(|e| IrohError::Backend(format!("write reply: {e}")))
    })
    .await;
    if written.is_err() {
        let _ = send.reset(crate::limits::REFUSED_SLOW.into());
    }
    written
}

/// A reply being read: its status and the rest of its body.
///
/// Holds the connection open until the body is read or the value dropped.
#[derive(Debug)]
pub struct Response {
    /// The status the handler answered with.
    pub status: u16,
    recv: RecvStream,
    _conn: Connection,
}

impl Response {
    /// Whether the status is a 2xx success.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The next body chunk, or `None` once the body is complete.
    pub async fn chunk(&mut self) -> IrohResult<Option<Bytes>> {
        self.recv
            .read_chunk(READ_CHUNK)
            .await
            .map_err(|e| IrohError::Backend(format!("read reply: {e}")))
    }

    /// The whole body, refusing one larger than `max` bytes.
    pub async fn bytes(mut self, max: usize) -> IrohResult<Bytes> {
        let body = self
            .recv
            .read_to_end(max)
            .await
            .map_err(|e| IrohError::Backend(format!("read reply: {e}")))?;
        Ok(Bytes::from(body))
    }
}

/// Send `request` to `remote` on `alpn` and return once the reply's status
/// has arrived. The body is read from the returned [`Response`].
pub async fn request(
    endpoint: &Endpoint,
    remote: impl Into<EndpointAddr>,
    alpn: &[u8],
    request: &[u8],
) -> IrohResult<Response> {
    let conn = endpoint
        .connect(remote, alpn)
        .await
        .map_err(|e| IrohError::Backend(format!("connect: {e}")))?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| IrohError::Backend(format!("open stream: {e}")))?;
    let len = u32::try_from(request.len()).map_err(|_| {
        IrohError::Backend(format!("request of {} bytes is too large", request.len()))
    })?;
    send.write_all(&len.to_le_bytes())
        .await
        .map_err(|e| IrohError::Backend(format!("write request: {e}")))?;
    send.write_all(request)
        .await
        .map_err(|e| IrohError::Backend(format!("write request: {e}")))?;
    send.finish()
        .map_err(|e| IrohError::Backend(format!("finish request: {e}")))?;
    let mut status = [0u8; 2];
    recv.read_exact(&mut status)
        .await
        .map_err(|e| IrohError::Backend(format!("read status: {e}")))?;
    Ok(Response {
        status: u16::from_le_bytes(status),
        recv,
        _conn: conn,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::endpoint::presets;
    use iroh::protocol::Router;

    /// A request is read whole when its bytes arrive, refused above the
    /// limit, and an announced length the peer does not send ends the read
    /// without reserving that length.
    #[tokio::test]
    async fn requests_are_read_within_their_limit_and_only_as_sent() {
        let mut ok = 3u32.to_le_bytes().to_vec();
        ok.extend_from_slice(b"abc");
        assert_eq!(read_request(&mut ok.as_slice(), 16).await.unwrap(), b"abc");

        let mut over = 17u32.to_le_bytes().to_vec();
        over.extend_from_slice(&[0; 17]);
        assert!(read_request(&mut over.as_slice(), 16).await.is_err());

        let mut short = (64u32 << 20).to_le_bytes().to_vec();
        short.extend_from_slice(b"only this");
        assert!(read_request(&mut short.as_slice(), 64 << 20).await.is_err());
        assert!(read_request(&mut &b"\x01\x00"[..], 16).await.is_err());
    }

    #[derive(Debug)]
    struct Chunks;

    #[async_trait]
    impl RequestHandler for Chunks {
        async fn handle(&self, _remote: EndpointId, request: Bytes) -> Reply {
            if request.as_ref() == b"fail" {
                let (tx, rx) = mpsc::channel(2);
                tokio::spawn(async move {
                    let _ = tx.send(Ok(Bytes::from_static(b"partial"))).await;
                    let _ = tx.send(Err("gone".into())).await;
                });
                return Reply::streamed(200, rx);
            }
            let (tx, rx) = mpsc::channel(4);
            tokio::spawn(async move {
                for part in [&b"a"[..], b"b", b"c"] {
                    let _ = tx.send(Ok(Bytes::copy_from_slice(part))).await;
                }
            });
            Reply::streamed(201, rx)
        }
    }

    /// Short timeouts and a small per-peer share, so the bounds show quickly.
    fn test_limits() -> AdmissionLimits {
        AdmissionLimits {
            max_in_flight: 64,
            max_in_flight_per_peer: 8,
            read_timeout: std::time::Duration::from_secs(2),
            write_timeout: std::time::Duration::from_secs(2),
        }
    }

    async fn pair(handler: Arc<dyn RequestHandler>, max: usize) -> (Router, Endpoint) {
        let server = Endpoint::builder(presets::Minimal).bind().await.unwrap();
        let router = Router::builder(server)
            .accept(
                ALPN_INFER,
                RequestProtocol::new("infer", handler, max, test_limits()),
            )
            .spawn();
        let client = Endpoint::builder(presets::Minimal).bind().await.unwrap();
        (router, client)
    }

    #[tokio::test]
    async fn a_streamed_body_arrives_whole_and_a_failed_one_errors() {
        let (router, client) = pair(Arc::new(Chunks), 64).await;
        let addr = router.endpoint().addr();
        let resp = request(&client, addr.clone(), ALPN_INFER, b"go")
            .await
            .unwrap();
        assert_eq!(resp.status, 201);
        assert_eq!(resp.bytes(64).await.unwrap().as_ref(), b"abc");
        // The reset may overtake the status on the wire; either way the
        // caller gets an error, never a truncated success.
        if let Ok(failed) = request(&client, addr, ALPN_INFER, b"fail").await {
            assert!(
                failed.bytes(64).await.is_err(),
                "a reset body is not a success"
            );
        }
    }

    #[tokio::test]
    async fn an_oversized_request_and_an_uninstalled_handler_are_refused() {
        let deferred = DeferredRequestHandler::new("infer");
        let (router, client) = pair(Arc::new(deferred.clone()), 8).await;
        let addr = router.endpoint().addr();
        assert!(
            request(&client, addr.clone(), ALPN_INFER, &[0u8; 9])
                .await
                .is_err()
        );
        let resp = request(&client, addr.clone(), ALPN_INFER, b"x")
            .await
            .unwrap();
        assert_eq!(resp.status, STATUS_UNAVAILABLE);
        deferred.set(Arc::new(Chunks));
        let resp = request(&client, addr, ALPN_INFER, b"x").await.unwrap();
        assert_eq!(resp.status, 201);
    }

    /// Open `streams` streams to `router` that each declare a large request
    /// and send only part of it, and report how many the server reset within
    /// `within`.
    async fn stalled_streams_reset(
        router: &Router,
        client: &Endpoint,
        streams: usize,
        within: std::time::Duration,
    ) -> usize {
        let conn = client
            .connect(router.endpoint().addr(), ALPN_INFER)
            .await
            .unwrap();
        let mut held = Vec::new();
        for _ in 0..streams {
            let (mut send, recv) = conn.open_bi().await.unwrap();
            send.write_all(&(4u32 * 1024 * 1024).to_le_bytes())
                .await
                .unwrap();
            send.write_all(&[0u8; 1024]).await.unwrap();
            held.push((send, recv));
        }
        let deadline = tokio::time::Instant::now() + within;
        let mut reset = 0;
        for (_, recv) in held.iter_mut() {
            let mut status = [0u8; 2];
            if matches!(
                tokio::time::timeout_at(deadline, recv.read_exact(&mut status)).await,
                Ok(Err(_))
            ) {
                reset += 1;
            }
        }
        reset
    }

    /// A peer that declares a request and then stops sending is cut off
    /// rather than holding the stream and its task forever.
    #[tokio::test]
    async fn a_stalled_request_is_reset() {
        let (router, client) = pair(Arc::new(Chunks), MAX_INFER_BYTES).await;
        let reset =
            stalled_streams_reset(&router, &client, 1, std::time::Duration::from_secs(10)).await;
        assert_eq!(reset, 1, "the server kept a stalled stream open");
    }

    /// One peer cannot hold more streams open than its share: the streams
    /// beyond it are refused at once, and a request on a free stream is
    /// served again once the stalled ones are cut off.
    #[tokio::test]
    async fn one_peer_cannot_hold_unbounded_streams() {
        let (router, client) = pair(Arc::new(Chunks), MAX_INFER_BYTES).await;
        let reset =
            stalled_streams_reset(&router, &client, 64, std::time::Duration::from_secs(1)).await;
        assert!(
            reset >= 64 - 8,
            "only {reset} of 64 stalled streams were refused"
        );
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let resp = request(&client, router.endpoint().addr(), ALPN_INFER, b"go")
            .await
            .unwrap();
        assert_eq!(resp.status, 201);
    }
}
