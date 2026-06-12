//! Per-request tenant Canton JWT propagation (Stage 2).
//!
//! The tenant's only credential is their `tnz_...` Tenzro API key. For
//! canton-scoped methods, `resolve_canton_jwt` in `rpc.rs` mints the
//! tenant's Canton JWT server-side from the OAuth client credentials
//! stored on the `ApiKeyRecord` (cached per client_id by the IdP
//! provisioner) and scopes it here; the node forwards it to the
//! Canton participant so the operator's credential never appears on
//! the wire for tenant requests. Tenants on their own upstream issuer
//! may instead present a JWT via the `X-Canton-Auth` header (BYO-issuer
//! escape hatch), which lands in the same slot.
//!
//! Threading the JWT explicitly through every canton handler would
//! touch dozens of signatures. We use a `tokio::task_local!` slot
//! instead: `handle_request` wraps the dispatch future in [`scope`],
//! canton handlers fetch the JWT via [`current`] just before calling
//! the bridge, and the slot vanishes with the future.
//!
//! `task_local!` (not `thread_local!`) is load-bearing: the dispatch
//! future is full of await points, so on a multi-threaded runtime a
//! thread-local slot would be read by whichever task happens to be on
//! the worker thread — cross-tenant leakage. Task-local storage rides
//! the future itself, so concurrent requests are isolated.

tokio::task_local! {
    static CANTON_JWT: Option<String>;
}

/// Runs `fut` with `jwt` installed in the task-local Canton JWT slot.
/// `handle_request` wraps the whole RPC dispatch in this.
pub async fn scope<F>(jwt: Option<String>, fut: F) -> F::Output
where
    F: std::future::Future,
{
    CANTON_JWT.scope(jwt, fut).await
}

/// Fetches the current task's Canton JWT, if any. Canton handlers
/// call this just before talking to the bridge adapter; the bridge
/// then uses `with_tenant_jwt` to scope the request to the tenant.
/// Returns `None` outside a [`scope`] (internal call paths), which
/// falls back to the operator token provider.
pub fn current() -> Option<String> {
    CANTON_JWT.try_with(|v| v.clone()).ok().flatten()
}
