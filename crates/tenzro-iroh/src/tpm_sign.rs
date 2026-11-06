//! `tenzro/tpm-sign` ALPN: a machine with no TPM asks a machine it is enrolled
//! with to sign for it, with a key that stays in that machine's TPM.
//!
//! Transport only: one request frame and one response frame per stream,
//! length-prefixed as on [`crate::consensus::ALPN_CONSENSUS`]. The server is
//! told which endpoint the connection authenticated (the QUIC peer key); the
//! request never names its sender. Whether that endpoint may sign anything is
//! the server's decision, not this module's.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr};
use tracing::trace;

use crate::consensus::{read_frame, write_frame};
use crate::error::{IrohError, IrohResult};
use crate::limits::{Admission, AdmissionLimits};

/// ALPN for signing on behalf of a machine without a TPM.
pub const ALPN_TPM_SIGN: &[u8] = b"tenzro/tpm-sign";

/// Largest request frame a server reads.
pub const MAX_REQUEST_BYTES: usize = 80 * 1024;

/// Largest response frame a requester reads.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Answers signing requests.
#[async_trait]
pub trait TpmSignServer: Send + Sync + fmt::Debug + 'static {
    /// The response to `request` from the endpoint `client` the connection
    /// authenticated.
    async fn serve(&self, client: [u8; 32], request: Vec<u8>) -> Vec<u8>;
}

/// Protocol handler serving [`ALPN_TPM_SIGN`].
#[derive(Debug, Clone)]
pub struct TpmSignProtocol {
    server: Arc<dyn TpmSignServer>,
    admission: Admission<iroh::EndpointId>,
}

impl TpmSignProtocol {
    /// A handler answering with `server`, serving at most `limits`.
    pub fn new(server: Arc<dyn TpmSignServer>, limits: AdmissionLimits) -> Self {
        Self {
            server,
            admission: Admission::new(limits),
        }
    }
}

impl ProtocolHandler for TpmSignProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let remote = conn.remote_id();
        let client: [u8; 32] = *remote.as_bytes();
        loop {
            let (mut send, mut recv) = match conn.accept_bi().await {
                Ok(pair) => pair,
                Err(e) => {
                    trace!(target: "tenzro_iroh::tpm_sign", error = %e, "tpm-sign connection closed");
                    return Ok(());
                }
            };
            let Some(permit) = self.admission.try_admit(remote) else {
                crate::limits::refuse(send, recv);
                continue;
            };
            let limits = *self.admission.limits();
            let server = self.server.clone();
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
                let response = server.serve(client, request).await;
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
pub async fn tpm_sign_request(
    endpoint: &Endpoint,
    peer: impl Into<EndpointAddr>,
    request: &[u8],
) -> IrohResult<Vec<u8>> {
    let peer: EndpointAddr = peer.into();
    let id = peer.id;
    let conn = endpoint
        .connect(peer, ALPN_TPM_SIGN)
        .await
        .map_err(|e| IrohError::Backend(format!("tpm-sign connect to {id}: {e}")))?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| IrohError::Backend(format!("tpm-sign open stream: {e}")))?;
    write_frame(&mut send, request).await?;
    let _ = send.finish();
    read_frame(&mut recv, MAX_RESPONSE_BYTES).await
}

/// The endpoint id a secret key stands for.
pub fn endpoint_id_of(secret: &[u8; 32]) -> [u8; 32] {
    *iroh::SecretKey::from_bytes(secret).public().as_bytes()
}

/// Binds an endpoint under `secret`, sends one request to `peer` (reached at
/// `addrs`) and closes the endpoint again.
pub async fn tpm_sign_request_once(
    secret: [u8; 32],
    peer: [u8; 32],
    addrs: &[std::net::SocketAddr],
    request: &[u8],
) -> IrohResult<Vec<u8>> {
    let endpoint = crate::identity_transport::base_builder()
        .secret_key(iroh::SecretKey::from_bytes(&secret))
        .bind()
        .await
        .map_err(|e| IrohError::Backend(format!("tpm-sign endpoint: {e}")))?;
    let id = iroh::EndpointId::from_bytes(&peer)
        .map_err(|e| IrohError::Backend(format!("tpm-sign provider id: {e}")))?;
    let mut addr = EndpointAddr::new(id);
    for a in addrs {
        addr = addr.with_ip_addr(*a);
    }
    let answer = tpm_sign_request(&endpoint, addr, request).await;
    endpoint.close().await;
    answer
}

/// Where the provider listens when the operator names no address: loopback
/// only, on a port the system picks.
pub const DEFAULT_TPM_SIGN_LISTEN: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);

/// Serves [`ALPN_TPM_SIGN`] under `secret` until the process ends, on the
/// `listen` addresses only (loopback when empty). Returns the bound
/// endpoint's address through `ready` once it listens.
pub async fn serve_tpm_sign(
    secret: [u8; 32],
    server: Arc<dyn TpmSignServer>,
    listen: Vec<SocketAddr>,
    ready: tokio::sync::oneshot::Sender<EndpointAddr>,
) -> IrohResult<()> {
    let listen = if listen.is_empty() {
        vec![DEFAULT_TPM_SIGN_LISTEN]
    } else {
        listen
    };
    let mut builder = crate::identity_transport::base_builder()
        .secret_key(iroh::SecretKey::from_bytes(&secret))
        .clear_ip_transports();
    for addr in &listen {
        builder = builder
            .bind_addr(*addr)
            .map_err(|e| IrohError::Backend(format!("tpm-sign listen address {addr}: {e}")))?;
    }
    // A provider reachable on loopback only asks no router to open a port.
    if listen.iter().all(|a| a.ip().is_loopback()) {
        builder = builder.portmapper_config(iroh::endpoint::PortmapperConfig::Disabled);
    }
    let endpoint = builder
        .bind()
        .await
        .map_err(|e| IrohError::Backend(format!("tpm-sign endpoint: {e}")))?;
    let router = iroh::protocol::Router::builder(endpoint.clone())
        .accept(
            ALPN_TPM_SIGN,
            TpmSignProtocol::new(server, AdmissionLimits::default()),
        )
        .spawn();
    let _ = ready.send(endpoint.addr());
    std::future::pending::<()>().await;
    drop(router);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Answers with the client id it was told, then the request.
    #[derive(Debug)]
    struct Echo;

    #[async_trait]
    impl TpmSignServer for Echo {
        async fn serve(&self, client: [u8; 32], request: Vec<u8>) -> Vec<u8> {
            let mut out = client.to_vec();
            out.extend_from_slice(&request);
            out
        }
    }

    #[tokio::test]
    async fn the_server_is_told_who_the_connection_authenticated() {
        let server = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .unwrap();
        let _router = iroh::protocol::Router::builder(server.clone())
            .accept(
                ALPN_TPM_SIGN,
                TpmSignProtocol::new(Arc::new(Echo), AdmissionLimits::default()),
            )
            .spawn();
        let client = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .unwrap();
        let response = tpm_sign_request(&client, server.addr(), b"abc")
            .await
            .unwrap();
        assert_eq!(&response[..32], client.id().as_bytes());
        assert_eq!(&response[32..], b"abc");
        let oversized = vec![0u8; MAX_REQUEST_BYTES + 1];
        assert!(
            tpm_sign_request(&client, server.addr(), &oversized)
                .await
                .is_err()
        );
    }

    /// The provider answers only on loopback when the operator names no
    /// address: every address it announces, and so every socket it bound,
    /// is a loopback one.
    #[tokio::test]
    async fn the_provider_listens_on_loopback_by_default() {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(serve_tpm_sign(
            [7u8; 32],
            Arc::new(Echo),
            Vec::new(),
            ready_tx,
        ));
        let addr = ready_rx.await.unwrap();
        task.abort();
        let ips: Vec<_> = addr.ip_addrs().copied().collect();
        assert!(!ips.is_empty(), "the provider announced no address");
        assert!(
            ips.iter().all(|a| a.ip().is_loopback()),
            "the provider listens beyond loopback: {ips:?}"
        );
    }

    /// An address the operator names is the only one the provider binds.
    #[tokio::test]
    async fn the_provider_listens_only_where_the_operator_says() {
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let listen: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            serve_tpm_sign([8u8; 32], Arc::new(Echo), vec![listen], ready_tx).await
        });
        let addr = ready_rx.await.unwrap();
        let ips: Vec<_> = addr.ip_addrs().copied().collect();
        assert_eq!(ips, vec![listen]);
        let client = crate::identity_transport::base_builder()
            .bind()
            .await
            .unwrap();
        let response = tpm_sign_request(&client, addr, b"abc").await.unwrap();
        assert_eq!(&response[32..], b"abc");
        task.abort();
    }
}
