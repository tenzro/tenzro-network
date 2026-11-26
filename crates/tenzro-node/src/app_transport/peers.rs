//! Streams between this node's app transport and other nodes', over the
//! node's iroh endpoint under `tenzro/app-stream/1`.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock, Weak};

use async_trait::async_trait;
use tenzro_iroh::app_stream::{BoxedRead, BoxedWrite, PeerDialer, PeerStreams};

use super::{Peers, Pipe};
use crate::node::TenzroNode;

/// Dials other nodes by machine DID from the node's iroh endpoint.
pub struct NodePeers {
    node: Arc<OnceLock<Weak<TenzroNode>>>,
    dialer: OnceLock<PeerDialer>,
}

impl NodePeers {
    /// Dialling from the node `node` comes to hold.
    pub fn new(node: Arc<OnceLock<Weak<TenzroNode>>>) -> Self {
        Self {
            node,
            dialer: OnceLock::new(),
        }
    }

    fn dialer(&self) -> Result<&PeerDialer, String> {
        if let Some(dialer) = self.dialer.get() {
            return Ok(dialer);
        }
        let node = self
            .node
            .get()
            .and_then(Weak::upgrade)
            .ok_or_else(|| "this node is not serving".to_string())?;
        let resolver = node
            .iroh_resolver()
            .ok_or_else(|| "this node has no iroh endpoint".to_string())?;
        let discovery = node
            .identity_transport
            .as_ref()
            .ok_or_else(|| "this node finds no other node by identity".to_string())?
            .store()
            .clone();
        Ok(self
            .dialer
            .get_or_init(|| PeerDialer::new(resolver.endpoint().clone(), discovery)))
    }
}

#[async_trait]
impl Peers for NodePeers {
    async fn dial(&self, did: &str) -> Result<Pipe, String> {
        if crate::identity_bootstrap::machine_did().as_deref() == Some(did) {
            return Err("a device signed in here reaches devices here without via".to_string());
        }
        self.dialer()?.open(did).await.map_err(|e| e.to_string())
    }
}

/// Hands the streams other nodes carry here to the app transport.
pub struct NodePeerStreams {
    node: Arc<OnceLock<Weak<TenzroNode>>>,
}

impl NodePeerStreams {
    /// Serving into the node `node` comes to hold.
    pub fn new(node: Arc<OnceLock<Weak<TenzroNode>>>) -> Self {
        Self { node }
    }
}

impl PeerStreams for NodePeerStreams {
    fn serve(
        &self,
        peer: String,
        recv: BoxedRead,
        send: BoxedWrite,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let listener = self
            .node
            .get()
            .and_then(Weak::upgrade)
            .and_then(|node| node.app_transport().cloned());
        Box::pin(async move {
            if let Some(listener) = listener {
                listener.serve_peer(peer, (recv, send)).await;
            }
        })
    }
}
