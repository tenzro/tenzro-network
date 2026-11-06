//! Shared application state and ordered teardown.
//!
//! Control runs the node **in-process** — there is no llama-server
//! sidecar and no supervised child. That has one consequence worth
//! stating explicitly, because it drives the shutdown ordering below:
//! every GGUF the node serves is loaded into *this* process's address
//! space, holding Metal (macOS) or CUDA (Linux) device buffers. Letting
//! those contexts drop implicitly while the tokio runtime is already
//! tearing down is how a clean quit turns into a driver-level crash on
//! exit. So [`graceful_shutdown`] unloads them by hand, in order,
//! before the node itself is drained.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;

/// In-flight assistant-stream cancellation tokens keyed by request id.
///
/// The conversational assistant drives token-by-token generation
/// through `ModelRuntime::generate_chat_stream`, which has no built-in
/// cancel. Registering a token per request is what lets the user stop a
/// running generation, and what lets shutdown pre-empt one.
pub type InflightMap = Arc<Mutex<HashMap<String, CancellationToken>>>;

/// The running node handle plus the assistant's in-flight stream map.
pub struct AppState {
    pub node: RwLock<Option<Arc<tenzro_node::NodeHandle>>>,
    pub inflight: InflightMap,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            node: RwLock::new(None),
            inflight: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

/// Ordered teardown.
///
/// 1. Cancel in-flight assistant streams so no generation task is still
///    driving a model when we start unloading them.
/// 2. Cancel in-flight model downloads, cleaning up their `.tmp` files
///    so the next launch doesn't inherit a half-written GGUF.
/// 3. Unload every loaded model, releasing GPU device buffers while the
///    runtime is still healthy.
/// 4. Drain the node so RocksDB flushes and the iroh endpoint closes cleanly.
///
/// Idempotent — safe to call from both the window-close path and the
/// signal handler, which can and do both fire on the same quit.
pub async fn graceful_shutdown(state: &AppState) {
    cancel_all_streams(state).await;
    crate::node::cancel_all_downloads(state).await;

    // Take the handle out first: any later call that finds `None` is a
    // no-op, which is what makes the double-fire case harmless.
    let node = {
        let mut guard = state.node.write().await;
        guard.take()
    };
    let Some(handle) = node else {
        return;
    };

    crate::node::unload_all_models(&handle).await;

    if let Err(e) = handle.shutdown_and_wait().await {
        tracing::warn!("node shutdown error: {}", e);
    }
}

/// Cancel every registered assistant stream and clear the map.
pub async fn cancel_all_streams(state: &AppState) {
    let mut inflight = state.inflight.lock().await;
    for (id, token) in inflight.drain() {
        tracing::debug!(request_id = %id, "cancelling assistant stream on shutdown");
        token.cancel();
    }
}
