//! `tenzro/shell` ALPN — interactive access to rented hardware.
//!
//! When an operator rents their node out, the renter should be able to use the
//! hardware directly rather than only through the node's RPCs. This is the
//! transport half of that: another ALPN on the endpoint every node already
//! binds (Phase C1), carrying a byte-duplex session.
//!
//! # Why this transport
//!
//! No inbound port. The endpoint is already NAT-traversing and already
//! identified by the node's key, which is the same move GCP's IAP and AWS's
//! SSM Session Manager make — reach the machine over a connection it
//! established, rather than opening a listener on it. Handing out an SSH key
//! and a public port is the alternative, and it is the thing this exists to
//! avoid.
//!
//! # Identity comes free
//!
//! An accepted iroh connection is already authenticated to the peer's
//! `EndpointId`, and since Phase C2 that is byte-identical to the peer's TDIP
//! Ed25519 key. So the handler is handed the caller's identity by the
//! transport; there is no bearer token to mint, leak, or replay. Authorization
//! is then a lookup — is there a live lease for this DID — which is what makes
//! "revoking the lease revokes access" true by construction rather than by
//! remembering to also revoke a credential.
//!
//! # What this module does not decide
//!
//! Whether the session is confined, and to what. This crate hands the streams
//! to a [`ShellHandler`] and knows nothing about sandboxes, PTYs, or leases —
//! the same separation that keeps A2A and MCP method definitions out of the
//! transport. The node's handler is where a session is refused for want of a
//! lease, or for want of a confinement boundary to run inside.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use iroh::endpoint::Connection;
// Re-exported so a handler implementation does not need a direct `iroh`
// dependency just to name the stream halves it is handed.
pub use iroh::endpoint::{RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler};
use parking_lot::RwLock;
use tracing::{debug, trace, warn};

use crate::error::IrohResult;

/// ALPN for interactive shell sessions against rented hardware.
pub const ALPN_SHELL: &[u8] = b"tenzro/shell";

/// The authenticated identity of the peer that opened a session.
///
/// The 32 bytes are the peer's iroh `EndpointId`, which since Phase C2 is the
/// same key as their TDIP DID — so this is the renter's identity as
/// established by the QUIC handshake, not a claim the renter made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionPeer(pub [u8; 32]);

impl SessionPeer {
    /// The raw public key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex, for log lines and lease lookups.
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for SessionPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Serves one interactive session.
#[async_trait]
pub trait ShellHandler: Send + Sync + fmt::Debug + 'static {
    /// Serve a session for `peer` over one bidirectional stream.
    ///
    /// Returning `Err` closes the stream. Implementations decide whether the
    /// peer is entitled to a session at all; the transport has already
    /// established *who* they are and nothing more.
    async fn serve_session(
        &self,
        peer: SessionPeer,
        send: SendStream,
        recv: RecvStream,
    ) -> IrohResult<()>;
}

/// Deferred [`ShellHandler`] trampoline.
///
/// Same chicken-and-egg as the A2A/MCP/HTTP dispatchers: the router fixes its
/// ALPN set at spawn time, but the node-side handler needs state that only
/// exists after the endpoint is bound. Until [`Self::set`] is called, sessions
/// are refused — refused rather than queued, because a renter waiting on a
/// hung stream cannot tell that from a node that is simply not offering
/// shell access.
#[derive(Debug, Clone, Default)]
pub struct DeferredShellHandler {
    inner: Arc<RwLock<Option<Arc<dyn ShellHandler>>>>,
}

impl DeferredShellHandler {
    /// Create an unbound handler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Install the backing handler. Idempotent.
    pub fn set(&self, handler: Arc<dyn ShellHandler>) {
        *self.inner.write() = Some(handler);
    }

    /// Has a backing handler been installed?
    pub fn is_ready(&self) -> bool {
        self.inner.read().is_some()
    }
}

#[async_trait]
impl ShellHandler for DeferredShellHandler {
    async fn serve_session(
        &self,
        peer: SessionPeer,
        send: SendStream,
        recv: RecvStream,
    ) -> IrohResult<()> {
        let backing = self.inner.read().clone();
        match backing {
            Some(h) => h.serve_session(peer, send, recv).await,
            None => Err(crate::error::IrohError::Unauthorized(
                "this node does not offer shell access".to_string(),
            )),
        }
    }
}

/// `iroh::ProtocolHandler` adapter registering [`ALPN_SHELL`].
#[derive(Debug, Clone)]
pub struct ShellProtocol {
    handler: Arc<dyn ShellHandler>,
}

impl ShellProtocol {
    /// Wrap a [`ShellHandler`] for registration under [`ALPN_SHELL`].
    pub fn new(handler: Arc<dyn ShellHandler>) -> Self {
        Self { handler }
    }
}

impl ProtocolHandler for ShellProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let remote = conn.remote_id();
        let peer = SessionPeer(*remote.as_bytes());
        debug!(
            target: "tenzro_iroh::shell",
            remote = %peer,
            "accepted iroh shell connection",
        );

        loop {
            let (send, recv) = match conn.accept_bi().await {
                Ok(pair) => pair,
                Err(e) => {
                    trace!(
                        target: "tenzro_iroh::shell",
                        remote = %peer,
                        error = %e,
                        "remote closed shell connection",
                    );
                    return Ok(());
                }
            };

            let handler = self.handler.clone();
            tokio::spawn(async move {
                if let Err(e) = handler.serve_session(peer, send, recv).await {
                    // Logged at warn on the *provider's* node: a refused
                    // session is something its operator wants to see, because
                    // the common cause is a lease that expired while someone
                    // was relying on it.
                    warn!(
                        target: "tenzro_iroh::shell",
                        remote = %peer,
                        error = %e,
                        "iroh shell session ended with an error",
                    );
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Never;

    #[async_trait]
    impl ShellHandler for Never {
        async fn serve_session(
            &self,
            _peer: SessionPeer,
            _send: SendStream,
            _recv: RecvStream,
        ) -> IrohResult<()> {
            unreachable!("not reached in these tests")
        }
    }

    #[test]
    fn an_unbound_handler_is_not_ready() {
        let h = DeferredShellHandler::new();
        assert!(!h.is_ready());
        h.set(Arc::new(Never));
        assert!(h.is_ready());
    }

    #[test]
    fn a_peer_renders_as_its_key() {
        let peer = SessionPeer([0xab; 32]);
        assert_eq!(peer.to_hex(), "ab".repeat(32));
        assert_eq!(peer.to_string(), peer.to_hex());
        assert_eq!(peer.as_bytes(), &[0xab; 32]);
    }
}
