//! Paths that already run on the node endpoint: consensus streams, block and
//! state sync, content-addressed blobs, remote shell, A2A, MCP, MoE and the
//! app-hosting HTTP forward.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use iroh::endpoint::Connection;
use iroh_blobs::{BlobsProtocol, api::downloader::Downloader, store::mem::MemStore};
use tenzro_iroh::{
    ALPN_A2A, ALPN_BLOCK_SYNC, ALPN_CONSENSUS, ALPN_MCP, ALPN_MOE, ALPN_STATE_SYNC,
    BlockSyncServer, ConsensusStreamHandler, DeferredBlockSyncServer, IrohResult,
    JsonRpcDispatcher, JsonRpcProtocol, McpProtocol, McpStreamHandler, RecvStream, SendStream,
    SnapshotDirectory, block_sync_request, jsonrpc_call, open_consensus_stream, read_frame,
    write_frame,
};

use crate::cluster::Cluster;

/// Answers every frame on a consensus stream with the caller's endpoint key.
#[derive(Debug)]
struct NameTheCaller;

#[async_trait]
impl ConsensusStreamHandler for NameTheCaller {
    fn admits(&self, _remote: &[u8; 32]) -> bool {
        true
    }

    async fn accept_stream(
        &self,
        remote: [u8; 32],
        _rtt: Duration,
        mut send: SendStream,
        mut recv: RecvStream,
    ) {
        while read_frame(&mut recv, 1024).await.is_ok() {
            if write_frame(&mut send, &remote).await.is_err() {
                return;
            }
        }
    }
}

#[tokio::test]
async fn consensus_stream() {
    let cluster = Cluster::start(|_, _, router| {
        router.accept(
            ALPN_CONSENSUS,
            tenzro_iroh::consensus::ConsensusProtocol::new(Arc::new(NameTheCaller)),
        )
    })
    .await;
    cluster
        .on_every_route(|client, server| async move {
            let (mut send, mut recv) = open_consensus_stream(&client.endpoint, server.id())
                .await
                .map_err(|e| e.to_string())?;
            write_frame(&mut send, b"vote")
                .await
                .map_err(|e| e.to_string())?;
            let named = read_frame(&mut recv, 64).await.map_err(|e| e.to_string())?;
            if named.as_slice() != client.id().as_bytes() {
                return Err("the server did not see the caller's key".into());
            }
            Ok(())
        })
        .await;
}

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
async fn block_sync() {
    let cluster = Cluster::start(|_, _, router| {
        let server = DeferredBlockSyncServer::new();
        server.set(Arc::new(Reverse));
        router.accept(
            ALPN_BLOCK_SYNC,
            tenzro_iroh::block_sync::BlockSyncProtocol::new(
                server,
                tenzro_iroh::limits::AdmissionLimits::default(),
            ),
        )
    })
    .await;
    cluster
        .on_every_route(|client, server| async move {
            let reply = block_sync_request(&client.endpoint, server.id(), b"tip")
                .await
                .map_err(|e| e.to_string())?;
            (reply == b"pit")
                .then_some(())
                .ok_or_else(|| "wrong reply".to_string())
        })
        .await;
}

/// Serves one manifest per node, at height 7.
#[derive(Debug)]
struct OneManifest([u8; 32]);

#[async_trait]
impl SnapshotDirectory for OneManifest {
    async fn manifest_for(&self, height: u64) -> Option<[u8; 32]> {
        (height == 7).then_some(self.0)
    }
}

#[tokio::test]
async fn state_sync() {
    let cluster = Cluster::start(|index, _, router| {
        router.accept(
            ALPN_STATE_SYNC,
            tenzro_iroh::state_sync::StateSyncProtocol::new(Arc::new(OneManifest(
                [index as u8; 32],
            ))),
        )
    })
    .await;
    cluster
        .on_every_route(|client, server| async move {
            let manifest =
                tenzro_iroh::state_sync::request_manifest(&client.endpoint, server.id(), 7)
                    .await
                    .map_err(|e| e.to_string())?;
            (manifest == Some([server.index as u8; 32]))
                .then_some(())
                .ok_or_else(|| format!("wrong manifest {manifest:?}"))
        })
        .await;
}

#[tokio::test]
async fn blobs() {
    let stores: Vec<MemStore> = (0..4).map(|_| MemStore::new()).collect();
    let mut hashes = Vec::new();
    for (i, store) in stores.iter().enumerate() {
        let tag = store
            .blobs()
            .add_bytes(format!("blob held by node {i}").into_bytes())
            .await
            .expect("add blob");
        hashes.push(tag.hash);
    }
    let cluster = Cluster::start(|index, _, router| {
        router.accept(iroh_blobs::ALPN, BlobsProtocol::new(&stores[index], None))
    })
    .await;
    let (stores, hashes) = (&stores, &hashes);
    cluster
        .on_every_route(|client, server| async move {
            let hash = hashes[server.index];
            let fetcher = MemStore::new();
            Downloader::new(&fetcher, &client.endpoint)
                .download(hash, vec![server.id()])
                .await
                .map_err(|e| e.to_string())?;
            let got = fetcher
                .blobs()
                .get_bytes(hash)
                .await
                .map_err(|e| e.to_string())?;
            let held = stores[server.index]
                .blobs()
                .get_bytes(hash)
                .await
                .map_err(|e| e.to_string())?;
            (got == held)
                .then_some(())
                .ok_or_else(|| "blob differs".to_string())
        })
        .await;
}

/// Open a stream on `alpn`, send `request`, and read the whole answer.
async fn exchange(
    client: &iroh::Endpoint,
    server: iroh::EndpointId,
    alpn: &[u8],
    request: &[u8],
) -> Result<(Connection, Vec<u8>), String> {
    let conn = client
        .connect(server, alpn)
        .await
        .map_err(|e| e.to_string())?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
    send.write_all(request).await.map_err(|e| e.to_string())?;
    send.finish().map_err(|e| e.to_string())?;
    let reply = recv.read_to_end(1 << 20).await.map_err(|e| e.to_string())?;
    Ok((conn, reply))
}

/// Echoes a JSON-RPC request back inside `result`.
#[derive(Debug)]
struct EchoRpc;

#[async_trait]
impl JsonRpcDispatcher for EchoRpc {
    async fn dispatch(&self, request: Bytes) -> IrohResult<Bytes> {
        let mut reply = br#"{"jsonrpc":"2.0","id":1,"result":"#.to_vec();
        reply.extend_from_slice(&request);
        reply.push(b'}');
        Ok(Bytes::from(reply))
    }
}

async fn jsonrpc_on_every_route(alpn: &'static [u8], protocol: fn() -> JsonRpcProtocol) {
    let cluster = Cluster::start(|_, _, router| router.accept(alpn, protocol())).await;
    cluster
        .on_every_route(|client, server| async move {
            let reply = jsonrpc_call(
                &client.endpoint,
                server.id(),
                alpn,
                Bytes::from_static(b"42"),
            )
            .await
            .map_err(|e| e.to_string())?;
            let value: serde_json::Value =
                serde_json::from_slice(&reply).map_err(|e| e.to_string())?;
            (value["result"] == 42)
                .then_some(())
                .ok_or_else(|| format!("reply {value}"))
        })
        .await;
}

#[tokio::test]
async fn a2a() {
    jsonrpc_on_every_route(ALPN_A2A, || {
        JsonRpcProtocol::a2a(
            Arc::new(EchoRpc),
            tenzro_iroh::limits::AdmissionLimits::default(),
        )
    })
    .await;
}

#[tokio::test]
async fn moe() {
    jsonrpc_on_every_route(ALPN_MOE, || {
        JsonRpcProtocol::moe(
            Arc::new(EchoRpc),
            tenzro_iroh::limits::AdmissionLimits::default(),
        )
    })
    .await;
}

/// Copies a raw stream back to its sender.
#[derive(Debug)]
struct EchoStream;

async fn echo(mut send: SendStream, mut recv: RecvStream) -> IrohResult<()> {
    let request = recv
        .read_to_end(1 << 20)
        .await
        .map_err(|e| tenzro_iroh::IrohError::Backend(e.to_string()))?;
    send.write_all(&request)
        .await
        .map_err(|e| tenzro_iroh::IrohError::Backend(e.to_string()))?;
    send.finish()
        .map_err(|e| tenzro_iroh::IrohError::Backend(e.to_string()))?;
    Ok(())
}

#[async_trait]
impl McpStreamHandler for EchoStream {
    async fn serve_stream(self: Arc<Self>, send: SendStream, recv: RecvStream) -> IrohResult<()> {
        echo(send, recv).await
    }
}

#[tokio::test]
async fn mcp() {
    let cluster = Cluster::start(|_, _, router| {
        router.accept(
            ALPN_MCP,
            McpProtocol::new(
                Arc::new(EchoStream),
                tenzro_iroh::limits::AdmissionLimits::default(),
            ),
        )
    })
    .await;
    cluster
        .on_every_route(|client, server| async move {
            let message = br#"{"jsonrpc":"2.0","method":"ping","id":1}"#;
            let (_conn, reply) = exchange(&client.endpoint, server.id(), ALPN_MCP, message).await?;
            (reply == message)
                .then_some(())
                .ok_or_else(|| "wrong reply".to_string())
        })
        .await;
}

/// The cluster's own shape: the outbound-only node cannot be dialed, and the
/// NAT-only and relay-only nodes publish no direct address.
#[tokio::test]
async fn topology_holds() {
    let cluster = Cluster::endpoints().await;
    for node in &cluster.nodes {
        let published = cluster.published(node);
        match node.reach {
            crate::cluster::Reach::OutboundOnly => assert!(published.is_none()),
            crate::cluster::Reach::Direct => {
                assert!(published.unwrap().ip_addrs().next().is_some())
            }
            _ => assert!(published.unwrap().ip_addrs().next().is_none()),
        }
    }
    let outbound = &cluster.nodes[2];
    let dial = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        cluster.nodes[0].endpoint.connect(outbound.id(), ALPN_A2A),
    )
    .await;
    assert!(
        !matches!(dial, Ok(Ok(_))),
        "the outbound-only node accepted a connection"
    );
}
