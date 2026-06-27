//! Library entry point for embedding a Tenzro node in another process.
//!
//! The binary entry point in `main.rs` owns its own signal handlers, side
//! services (RPC / MCP / A2A / web), and shutdown choreography. A library
//! consumer — the desktop app, an embedded test harness, an external SDK
//! — needs none of that and cannot easily replicate it. [`spawn_in_background`]
//! moves a built [`TenzroNode`] into a managed tokio task and returns a
//! [`NodeHandle`] that exposes:
//!
//! - direct `Arc<TenzroNode>` access for in-process dispatch (the embedded
//!   counterpart to the binary's `Arc<TenzroNode>` wrapping in `main.rs`),
//! - graceful shutdown via [`NodeHandle::shutdown`] which mirrors the
//!   `NodeEvent::Shutdown` + grace-period pattern the binary uses,
//! - a [`tokio::sync::watch`] subscription of [`NodeStatus`] snapshots
//!   refreshed on a fixed interval, via [`NodeHandle::subscribe_status`].
//!
//! The handle does not run the side services (RPC / MCP / A2A / web) —
//! those are wired in `main.rs` from `node.rpc_server()` and friends. A
//! library consumer that wants those surfaces calls into the node Arc
//! directly; for in-process RPC dispatch use [`crate::dispatch_embedded`].

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::event_loop::NodeEvent;
use crate::node::{NodeStatus, TenzroNode};
use crate::{NodeConfig, Result};

/// How often the background status poller refreshes the watch channel.
/// One second keeps the UI responsive without making the watcher a hot
/// loop. Consumers that need a tighter cadence can call
/// [`TenzroNode::status`] directly via [`NodeHandle::node`].
const STATUS_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Grace period the shutdown path waits after sending `NodeEvent::Shutdown`
/// so the event loop can drain in-flight work. Matches the 5-second window
/// the binary's `main.rs` uses before exiting.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Handle to a running Tenzro node spawned via [`spawn_in_background`].
///
/// Cheap to clone — internally it holds `Arc`s and channel
/// senders/receivers. Dropping the last handle does **not** stop the
/// node; call [`shutdown`] explicitly. This matches the embedded use
/// case where the UI thread holds one handle, Tauri-managed state holds
/// another, and shutdown is an explicit operator action triggered on
/// window close.
///
/// [`shutdown`]: NodeHandle::shutdown
#[derive(Clone)]
pub struct NodeHandle {
    inner: Arc<HandleInner>,
}

struct HandleInner {
    /// The running node. `Arc<TenzroNode>` rather than
    /// `Arc<Mutex<TenzroNode>>` because — once `start()` returns —
    /// every accessor on the node takes `&self`, mirroring the binary
    /// `main.rs` pattern that wraps the node in `Arc::new(node)` post
    /// `start()` and never reaches for `&mut self` again. Shutdown
    /// flows through the event-loop channel via
    /// [`TenzroNode::event_sender`], not through `stop()`.
    node: Arc<TenzroNode>,
    /// Latest [`NodeStatus`] snapshot. Updated by the background poller
    /// every [`STATUS_POLL_INTERVAL`].
    status_rx: watch::Receiver<NodeStatus>,
    /// Set when [`NodeHandle::shutdown`] is called. The background task
    /// observes this and exits its loop after dispatching the shutdown
    /// event + waiting out the grace period.
    shutdown_tx: watch::Sender<bool>,
    /// Join handle for the background task. `Mutex` so the first
    /// [`shutdown_and_wait`](NodeHandle::shutdown_and_wait) call can take
    /// it; subsequent calls return `Ok(())` immediately.
    join: Mutex<Option<JoinHandle<()>>>,
}

impl NodeHandle {
    /// Returns the most recent [`NodeStatus`] snapshot without waiting for
    /// the next poll tick.
    pub fn current_status(&self) -> NodeStatus {
        self.inner.status_rx.borrow().clone()
    }

    /// Subscribe to live status updates. Each refresh of the background
    /// poller marks the channel as changed; the consumer can either call
    /// `borrow()` for the latest snapshot or `changed().await` to be woken
    /// on the next refresh.
    pub fn subscribe_status(&self) -> watch::Receiver<NodeStatus> {
        self.inner.status_rx.clone()
    }

    /// Direct access to the running node Arc. Use this to reach into the
    /// node for accessors that the handle does not surface — e.g. the
    /// inference router Arc (`node().inference_router_arc()`), the model
    /// runtime Arc (`node().model_runtime_arc()`), or for in-process
    /// RPC dispatch via [`crate::dispatch_embedded`].
    pub fn node(&self) -> Arc<TenzroNode> {
        self.inner.node.clone()
    }

    /// Signal the background task to stop the node and exit. Returns
    /// immediately. Use [`shutdown_and_wait`](Self::shutdown_and_wait) if
    /// the caller needs to know when the node has actually stopped.
    pub fn shutdown(&self) {
        let _ = self.inner.shutdown_tx.send(true);
    }

    /// Signal shutdown and wait for the background task to drain.
    /// Subsequent calls return `Ok(())` because the join handle is taken
    /// on first call.
    pub async fn shutdown_and_wait(&self) -> Result<()> {
        let _ = self.inner.shutdown_tx.send(true);
        let join = self.inner.join.lock().await.take();
        if let Some(join) = join
            && let Err(e) = join.await {
                warn!("NodeHandle background task panicked: {}", e);
            }
        Ok(())
    }
}

/// Build a node from the given config and run it on a background tokio
/// task. The returned [`NodeHandle`] is the only thing the caller needs to
/// hold; the node's tokio tasks live for the duration of the runtime.
///
/// This is the in-process counterpart to `main.rs` — it does **not** spawn
/// the side services (RPC / MCP / A2A / web). Library consumers that need
/// those should call [`NodeHandle::node`] and start them off the inner
/// reference, or invoke [`crate::dispatch_embedded`] directly without
/// exposing any HTTP surface at all.
pub async fn spawn_in_background(config: NodeConfig) -> Result<NodeHandle> {
    spawn_in_background_inner(config, None).await
}

/// Like [`spawn_in_background`], but injects a keystore-password source so the
/// wallet PERSISTS across restarts (FROST key shares written to / loaded from
/// the encrypted on-disk keystore). The unlocker is a trait object, so the node
/// stays platform-agnostic: desktop apps pass a biometric Secure-Enclave
/// unlocker (`tenzro-device-key`), headless nodes an env/file/KMS one. See
/// [`TenzroNode::with_keystore_unlocker`] for the contract.
pub async fn spawn_in_background_with_unlocker(
    config: NodeConfig,
    unlocker: Arc<dyn tenzro_keystore_unlock::KeystoreUnlocker>,
) -> Result<NodeHandle> {
    spawn_in_background_inner(config, Some(unlocker)).await
}

async fn spawn_in_background_inner(
    config: NodeConfig,
    unlocker: Option<Arc<dyn tenzro_keystore_unlock::KeystoreUnlocker>>,
) -> Result<NodeHandle> {
    let mut node = TenzroNode::new(config).await?;
    if let Some(unlocker) = unlocker {
        node.set_keystore_unlocker(unlocker);
    }
    node.start().await?;

    let initial_status = node.status().await;
    let (status_tx, status_rx) = watch::channel(initial_status);
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    let node = Arc::new(node);
    let node_for_task = node.clone();

    let join = tokio::spawn(async move {
        info!("NodeHandle background task started");
        let mut ticker = tokio::time::interval(STATUS_POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let status = node_for_task.status().await;
                    if status_tx.send(status).is_err() {
                        // No subscribers and no current_status holder left.
                        // Keep polling — the watch channel auto-recovers on
                        // the next subscribe — but log so operators see why
                        // the channel went quiet.
                        debug!("NodeHandle status watch channel has no receivers");
                    }
                }
                changed = shutdown_rx.changed() => {
                    if changed.is_err() {
                        // Sender dropped without a value; treat as shutdown.
                        break;
                    }
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }

        info!("NodeHandle initiating shutdown");
        if let Some(event_tx) = node_for_task.event_sender() {
            if let Err(e) = event_tx.try_send(NodeEvent::Shutdown) {
                warn!("NodeHandle failed to send Shutdown event: {}", e);
            }
        } else {
            warn!("NodeHandle: event_sender unavailable; shutdown is best-effort");
        }

        // Mirror the binary's 5-second grace period so the event loop can
        // drain consensus / network / RPC state cleanly.
        tokio::time::sleep(SHUTDOWN_GRACE).await;
        info!("NodeHandle background task exited");
    });

    Ok(NodeHandle {
        inner: Arc::new(HandleInner {
            node,
            status_rx,
            shutdown_tx,
            join: Mutex::new(Some(join)),
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn spawn_and_shutdown_default_config() {
        let config = NodeConfig::default();
        let handle = spawn_in_background(config).await.expect("spawn");

        // Status channel produces an initial snapshot synchronously.
        let s = handle.current_status();
        assert_eq!(s.roles, handle.current_status().roles);

        // node() returns an Arc to the running node — the in-process
        // counterpart to `main.rs`'s `Arc::new(node)` post-start.
        let node = handle.node();
        assert!(Arc::strong_count(&node) >= 2);

        handle.shutdown_and_wait().await.expect("shutdown");

        // Second call is a no-op.
        handle.shutdown_and_wait().await.expect("idempotent shutdown");
    }
}
