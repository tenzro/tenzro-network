//! Generative media client: the media catalog, and renders on a node or a
//! provider serving the model.
//!
//! # Example
//!
//! ```no_run
//! # use tenzro_sdk::TenzroClient;
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
//! let catalog = client.media_gen().list_catalog().await?;
//! println!("{} models", catalog.count);
//!
//! let render = client
//!     .media_gen()
//!     .render("z-image-turbo", "text2image", serde_json::json!({
//!         "prompt": "a lighthouse in fog",
//!         "width": 1024,
//!         "height": 1024,
//!         "steps": 8,
//!         "seed": 7
//!     }), &[], None)
//!     .await?;
//! println!("{}", render["output_blake3"]);
//! # Ok(())
//! # }
//! ```

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// What one input is to the pipeline that renders it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaGenInputRole {
    /// The frame a video starts on.
    FirstFrame,
    /// The frame a video ends on.
    LastFrame,
    /// An image whose subject or style the output follows.
    Reference,
    /// An image the output edits; several are read in order.
    EditSource,
    /// The region of the edit source an edit may change.
    Mask,
    /// A robot observation an action policy acts on.
    Observation,
}

/// One render input (`params.inputs[]`): bytes named by their SHA-256
/// `hash` and the `role` they play, sent alongside in `inputs_base64`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaGenInput {
    /// What the input is to the pipeline.
    pub role: MediaGenInputRole,
    /// SHA-256 of the input bytes, serialized as the spec's other hashes are
    /// (the 32 digest bytes).
    pub hash: [u8; 32],
}

/// Result of `tenzro_mediaGen_listCatalog`. Entries are passed through as
/// `serde_json::Value` so a catalog refresh doesn't break compiled callers;
/// consumers wanting typed access deserialize `tenzro_model::MediaGenModelEntry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaGenCatalog {
    #[serde(default)]
    pub models: Vec<serde_json::Value>,
    #[serde(default)]
    pub count: usize,
}

/// Generative media client.
#[derive(Clone)]
pub struct MediaGenClient {
    rpc: Arc<RpcClient>,
}

impl MediaGenClient {
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// The curated generative-media catalog: ungated, diffusers-loadable
    /// models, each carrying its default resolution, step count, frame count,
    /// VRAM floor, license tier, and — where the schedule splits — the
    /// expert pair and the timestep boundary between them.
    pub async fn list_catalog(&self) -> SdkResult<MediaGenCatalog> {
        self.rpc
            .call("tenzro_mediaGen_listCatalog", serde_json::json!({}))
            .await
    }

    /// Render one output now, on the node or on a provider serving the
    /// model. `params` is the `MediaGenParams` object with a `seed`;
    /// `inputs_base64` the bytes of each input `params.inputs` names, in
    /// order; `verification` one of `none`, `receipt`, `optimistic`, `tee`.
    /// The answer carries what its signed receipt commits to (`mime`,
    /// `output_sha256`, `output_bytes`, `fingerprint`, `tolerance_bps`), the
    /// receipt, the price, and `output_blake3`, fetched with
    /// `tenzro_iroh_fetchBlob`.
    pub async fn render(
        &self,
        model_id: &str,
        kind: &str,
        params: serde_json::Value,
        inputs_base64: &[String],
        verification: Option<&str>,
    ) -> SdkResult<serde_json::Value> {
        let mut req = serde_json::json!({
            "model_id": model_id,
            "kind": kind,
            "params": params,
            "inputs_base64": inputs_base64,
        });
        if let Some(v) = verification {
            req["verification"] = v.into();
        }
        self.rpc.call("tenzro_mediaGen_render", req).await
    }

    /// Calls `tenzro_loadMediaModel`: load media model.
    pub async fn load_media_model(&self, model_id: &str) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_loadMediaModel",
                serde_json::json!({ "model_id": model_id }),
            )
            .await
    }

    /// Calls `tenzro_unloadMediaModel`: unload media model.
    pub async fn unload_media_model(&self, model_id: &str) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_unloadMediaModel",
                serde_json::json!({ "model_id": model_id }),
            )
            .await
    }
}
