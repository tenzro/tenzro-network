//! Per-request Canton network selection.
//!
//! A node may serve more than one Canton network (devnet, mainnet)
//! from a single RPC endpoint. Each network is a distinct ledger with
//! distinct parties and assets, so every canton-scoped request has to
//! resolve to exactly one of them. The api-key gate in `rpc.rs`
//! resolves the target from the request's optional `canton_network`
//! param — validated against the key's authorized set — and scopes it
//! here; `canton_adapter_or_err` reads it back to pick the adapter.
//!
//! Threading the network explicitly through every canton handler would
//! touch dozens of signatures. We use a `tokio::task_local!` slot
//! instead: the gate wraps the dispatch future in [`scope`], the
//! adapter resolver fetches the network via [`current`], and the slot
//! vanishes with the future.
//!
//! `task_local!` (not `thread_local!`) is required for correctness: the dispatch
//! future is full of await points, so on a multi-threaded runtime a
//! thread-local slot would be read by whichever task happens to be on
//! the worker thread — a request against devnet could be answered by
//! the mainnet participant. Task-local storage rides the future
//! itself, so concurrent requests are isolated.

use crate::config::CantonNetwork;

tokio::task_local! {
    static CANTON_NETWORK: Option<CantonNetwork>;
}

/// Runs `fut` with `net` installed in the task-local Canton network
/// slot. The api-key gate wraps the RPC dispatch in this.
pub async fn scope<F>(net: Option<CantonNetwork>, fut: F) -> F::Output
where
    F: std::future::Future,
{
    CANTON_NETWORK.scope(net, fut).await
}

/// Fetches the Canton network resolved for the current request, if
/// any. Returns `None` outside a [`scope`] (internal call paths such as
/// the workflow receipt mirror), where the caller falls back to the
/// configured default network.
pub fn current() -> Option<CantonNetwork> {
    CANTON_NETWORK.try_with(|v| *v).ok().flatten()
}
