//! Bridge from `tenzro_model::BlobFetcher` to
//! `tenzro_iroh::IrohBackedResolver`.
//!
//! `tenzro-model` and `tenzro-iroh` are sibling leaves in the dependency
//! graph — neither depends on the other. The trait that lets the HF
//! artifact downloader fall through to a `tenzro://` peer-fetch path lives
//! in `tenzro-model` (so the model crate stays free of any iroh runtime
//! dep), and the concrete iroh-blobs-backed resolver lives in
//! `tenzro-iroh`. This adapter, owned by `tenzro-node`, glues the two
//! together — it is the only place that depends on both crates and can
//! therefore implement the trait against the resolver.
//!
//! At node startup, the node's single [`IrohBackedResolver`] is wrapped
//! in [`IrohBlobFetcher`] and passed to
//! `HfArtifactDownloader::with_blob_fetcher`. From that point any
//! [`tenzro_model::ArtifactSpec`] carrying a `peer_hint` first tries to
//! pull the file from peers over `tenzro://blob/<blake3>` and only falls
//! back to the HF CDN on failure. Successful HF downloads are
//! opportunistically re-published so neighbour nodes can fetch from us
//! next time — Phase B1's `IrohGradientStore` and Phase B2's
//! `IrohSealedShardStore` follow the same opportunistic-publish pattern
//! for gradients and sealed shards respectively.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use tenzro_iroh::{IrohBackedResolver, IrohResolver};
use tenzro_model::BlobFetcher;
use tenzro_types::tenzro_uri::TenzroUri;

/// `BlobFetcher` impl backed by [`IrohBackedResolver`]. See module docs.
pub struct IrohBlobFetcher {
    resolver: Arc<IrohBackedResolver>,
}

impl IrohBlobFetcher {
    /// Wrap an existing iroh resolver. The resolver is shared (Arc) — the
    /// same instance services agent-memory, gradient store, sealed-shard
    /// store, DA backend, and now model weight distribution.
    pub fn new(resolver: Arc<IrohBackedResolver>) -> Self {
        Self { resolver }
    }

    /// Convenience: wrap and return as `Arc<dyn BlobFetcher>` for direct
    /// pass to `HfArtifactDownloader::with_blob_fetcher`.
    pub fn arc(resolver: Arc<IrohBackedResolver>) -> Arc<dyn BlobFetcher> {
        Arc::new(Self::new(resolver))
    }
}

#[async_trait]
impl BlobFetcher for IrohBlobFetcher {
    async fn fetch(&self, uri: &TenzroUri) -> Result<Bytes, String> {
        self.resolver
            .fetch_bytes(uri)
            .await
            .map_err(|e| e.to_string())
    }

    async fn publish(&self, bytes: Bytes) -> Result<TenzroUri, String> {
        self.resolver
            .publish_bytes(bytes)
            .await
            .map_err(|e| e.to_string())
    }

    async fn publish_file(&self, path: &Path) -> Result<TenzroUri, String> {
        self.resolver
            .publish_path(path)
            .await
            .map_err(|e| e.to_string())
    }
}
