//! State-sync snapshot client for Tenzro Network.
//!
//! Wraps the snapshot RPCs a node serves. Both are reads. The snapshot data
//! itself (the anchor chain and the state buckets) is fetched over the node's
//! iroh state-sync protocol from the `endpoint_id` `tenzro_listSnapshots`
//! reports, and verified against the manifest: every bucket against its
//! summary, and the summaries against the state root. See
//! `crates/tenzro-node/src/snapshot.rs`.
//!
//! - `tenzro_listSnapshots` — the snapshots this node holds, and the iroh
//!   endpoint it serves them from.
//! - `tenzro_getSnapshotManifest` — the full manifest for the snapshot at
//!   `height`.
//!
//! # Example
//!
//! ```no_run
//! # use tenzro_sdk::TenzroClient;
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
//! let snap = client.snapshot();
//!
//! let listed = snap.list_snapshots().await?;
//! for s in &listed.snapshots {
//!     println!("snapshot h={} buckets={}", s.height, s.buckets);
//! }
//! # Ok(())
//! # }
//! ```

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// State-sync snapshot client.
#[derive(Clone)]
pub struct SnapshotClient {
    rpc: Arc<RpcClient>,
}

impl SnapshotClient {
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// The snapshots this node holds, and the iroh endpoint it serves them
    /// from.
    pub async fn list_snapshots(&self) -> SdkResult<SnapshotList> {
        self.rpc
            .call("tenzro_listSnapshots", serde_json::json!([]))
            .await
    }

    /// The full manifest for the snapshot at `height`. Returns the node's
    /// `-32004 no snapshot at height` error if it holds none there.
    pub async fn get_snapshot_manifest(&self, height: u64) -> SdkResult<SnapshotManifest> {
        self.rpc
            .call(
                "tenzro_getSnapshotManifest",
                serde_json::json!([{ "height": height }]),
            )
            .await
    }
}

/// One snapshot, as `tenzro_listSnapshots` lists it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotSummary {
    /// Height of the committed state.
    pub height: u64,
    /// State root at that height.
    pub state_root: String,
    /// BLAKE3 hash (hex) of the manifest blob.
    pub manifest_blob: String,
    /// Number of state buckets.
    pub buckets: usize,
}

/// Result of `tenzro_listSnapshots`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotList {
    /// The snapshots this node holds.
    pub snapshots: Vec<SnapshotSummary>,
    /// The iroh endpoint the snapshot data is served from, when the node
    /// runs one.
    pub endpoint_id: Option<String>,
}

/// A snapshot manifest, as `tenzro_getSnapshotManifest` returns it. A
/// joining node checks that the bucket summaries fold to `state_root`, that
/// `state_root` is the one a trusted block commits to, and every fetched
/// bucket against its summary before applying it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifest {
    /// Height of the committed state.
    pub height: u64,
    /// The state root at `height`.
    pub state_root: serde_json::Value,
    /// BLAKE3 hash of the blob holding the anchor chain of blocks.
    pub anchor_chain: serde_json::Value,
    /// Every non-empty bucket, in index order: its summary, blob hash and
    /// entry count.
    pub buckets: Vec<serde_json::Value>,
}
