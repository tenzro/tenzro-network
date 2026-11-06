//! `tenzro/block-sync` ALPN — how a node that is behind fetches blocks and
//! the checkpoint evidence covering them.
//!
//! Transport only: one request frame and one response frame per stream,
//! length-prefixed as on [`crate::consensus::ALPN_CONSENSUS`]. The bytes are
//! opaque here. Nothing served is trusted for being served: the requester
//! imports a block only when a checkpoint certificate it verifies covers it.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr};
use parking_lot::RwLock;
use tracing::trace;

use crate::consensus::{read_frame, write_frame};
use crate::error::{IrohError, IrohResult};
use crate::limits::{Admission, AdmissionLimits};

/// ALPN for block sync.
pub const ALPN_BLOCK_SYNC: &[u8] = b"tenzro/block-sync";

/// Largest request frame a server reads.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// Largest response frame a requester reads.
pub const MAX_RESPONSE_BYTES: usize = 16 << 20;

/// Answers block-sync requests.
#[async_trait]
pub trait BlockSyncServer: Send + Sync + fmt::Debug + 'static {
    /// The response to `request`.
    async fn serve(&self, request: Vec<u8>) -> Vec<u8>;
}

/// A server installed once the node's block store is up. Until then streams
/// are closed at once.
#[derive(Debug, Clone, Default)]
pub struct DeferredBlockSyncServer {
    inner: Arc<RwLock<Option<Arc<dyn BlockSyncServer>>>>,
}

impl DeferredBlockSyncServer {
    /// An unbound server.
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs the backing server.
    pub fn set(&self, server: Arc<dyn BlockSyncServer>) {
        *self.inner.write() = Some(server);
    }
}

/// Protocol handler serving [`ALPN_BLOCK_SYNC`].
#[derive(Debug, Clone)]
pub struct BlockSyncProtocol {
    server: DeferredBlockSyncServer,
    admission: Admission<iroh::EndpointId>,
}

impl BlockSyncProtocol {
    /// A handler answering with `server`, serving at most `limits`.
    pub fn new(server: DeferredBlockSyncServer, limits: AdmissionLimits) -> Self {
        Self {
            server,
            admission: Admission::new(limits),
        }
    }
}

impl ProtocolHandler for BlockSyncProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let remote = conn.remote_id();
        loop {
            let (mut send, mut recv) = match conn.accept_bi().await {
                Ok(pair) => pair,
                Err(e) => {
                    trace!(target: "tenzro_iroh::block_sync", error = %e, "block-sync connection closed");
                    return Ok(());
                }
            };
            let Some(server) = self.server.inner.read().clone() else {
                return Ok(());
            };
            let Some(permit) = self.admission.try_admit(remote) else {
                trace!(target: "tenzro_iroh::block_sync", %remote, "block-sync stream refused: at capacity");
                crate::limits::refuse(send, recv);
                continue;
            };
            let limits = *self.admission.limits();
            tokio::spawn(async move {
                let _permit = permit;
                let request = crate::limits::within(
                    limits.read_timeout,
                    "receiving the request",
                    read_frame(&mut recv, MAX_REQUEST_BYTES),
                )
                .await;
                let Ok(request) = request else {
                    crate::limits::cut_off(&mut send, &mut recv);
                    return;
                };
                let response = server.serve(request).await;
                let written = crate::limits::within(
                    limits.write_timeout,
                    "sending the response",
                    write_frame(&mut send, &response),
                )
                .await;
                match written {
                    Ok(()) => {
                        let _ = send.finish();
                    }
                    Err(_) => crate::limits::cut_off(&mut send, &mut recv),
                }
            });
        }
    }
}

/// Sends one request to `peer` and returns its response.
pub async fn block_sync_request(
    endpoint: &Endpoint,
    peer: impl Into<EndpointAddr>,
    request: &[u8],
) -> IrohResult<Vec<u8>> {
    let peer: EndpointAddr = peer.into();
    let id = peer.id;
    let conn = endpoint
        .connect(peer, ALPN_BLOCK_SYNC)
        .await
        .map_err(|e| IrohError::Backend(format!("block-sync connect to {id}: {e}")))?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| IrohError::Backend(format!("block-sync open stream: {e}")))?;
    write_frame(&mut send, request).await?;
    let _ = send.finish();
    read_frame(&mut recv, MAX_RESPONSE_BYTES).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Reverse;

    #[async_trait]
    impl BlockSyncServer for Reverse {
        async fn serve(&self, mut request: Vec<u8>) -> Vec<u8> {
            request.reverse();
            request
        }
    }

    #[tokio::test]
    async fn a_request_gets_the_servers_response() {
        let deferred = DeferredBlockSyncServer::new();
        let server = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .unwrap();
        let _router = iroh::protocol::Router::builder(server.clone())
            .accept(
                ALPN_BLOCK_SYNC,
                BlockSyncProtocol::new(deferred.clone(), AdmissionLimits::default()),
            )
            .spawn();
        deferred.set(Arc::new(Reverse));
        let client = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .unwrap();
        let response = block_sync_request(&client, server.addr(), b"abc")
            .await
            .unwrap();
        assert_eq!(response, b"cba");
        let oversized = vec![0u8; MAX_REQUEST_BYTES + 1];
        assert!(
            block_sync_request(&client, server.addr(), &oversized)
                .await
                .is_err()
        );
    }

    /// A requester that declares a frame and stops sending is cut off.
    #[tokio::test]
    async fn a_stalled_request_is_cut_off() {
        let deferred = DeferredBlockSyncServer::new();
        deferred.set(Arc::new(Reverse));
        let server = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .unwrap();
        let limits = AdmissionLimits {
            read_timeout: std::time::Duration::from_secs(2),
            ..AdmissionLimits::default()
        };
        let _router = iroh::protocol::Router::builder(server.clone())
            .accept(
                ALPN_BLOCK_SYNC,
                BlockSyncProtocol::new(deferred.clone(), limits),
            )
            .spawn();
        let client = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .unwrap();
        let conn = client
            .connect(server.addr(), ALPN_BLOCK_SYNC)
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&(MAX_REQUEST_BYTES as u32).to_be_bytes())
            .await
            .unwrap();
        send.write_all(&[0u8; 16]).await.unwrap();
        let mut len = [0u8; 4];
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            recv.read_exact(&mut len),
        )
        .await;
        assert!(
            matches!(outcome, Ok(Err(_))),
            "the server kept a stalled block-sync stream open"
        );
    }
}
