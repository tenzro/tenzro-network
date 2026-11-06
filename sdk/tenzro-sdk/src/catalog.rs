//! The model catalog a node serves, and the engine releases it reports.
//!
//! The catalog is published data: each model is an entry a publisher signs
//! on its own hardware, and a node serves the entries of the publishers its
//! operator names (or every bonded publisher). Entries are published with
//! [`crate::trust::TrustClient::submit`].

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde_json::{Value, json};
use std::sync::Arc;

/// Model catalog client.
pub struct CatalogClient {
    rpc: Arc<RpcClient>,
}

impl CatalogClient {
    /// Creates a new catalog client.
    pub fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Every entry the node serves, optionally only of one engine family
    /// (`gguf`, `onnx-vision`, `media-gen`, ...), with the named
    /// publishers and the
    /// publishers the catalog was assembled from and each published model
    /// left out with the reason.
    pub async fn list(&self, engine: Option<&str>) -> SdkResult<Value> {
        self.rpc
            .call("tenzro_listCatalog", json!({ "engine": engine }))
            .await
    }

    /// One model's entry, its publishers and whether the operator's own
    /// token is needed to fetch its weights. A model the node does not serve
    /// is an error naming the reason.
    pub async fn entry(&self, model: &str) -> SdkResult<Value> {
        self.rpc
            .call("tenzro_getCatalogEntry", json!({ "model": model }))
            .await
    }

    /// The engine releases from the publishers the node's operator trusts for
    /// releases, newest first, each marked `newer` than the running build.
    /// The node installs nothing; its operator applies a release.
    pub async fn engine_releases(&self) -> SdkResult<Value> {
        self.rpc.call("tenzro_getEngineReleases", json!({})).await
    }
}
