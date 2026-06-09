//! Per-request tenant Canton JWT propagation (Stage 2).
//!
//! Stage 2 of the Canton multi-tenant model has tenants present their
//! own Canton JWT alongside their Tenzro API key, via the
//! `X-Canton-Auth` header. The node forwards the JWT as-is to the
//! Canton participant so Canton's IDP routing kicks in and the
//! operator's credential never appears on the wire.
//!
//! Threading the JWT explicitly through every canton handler would
//! touch dozens of signatures. We use a task-local slot instead: the
//! top-level RPC dispatch installs the JWT into the task-local before
//! invoking `handle_request`, canton handlers fetch it just before
//! calling the bridge, and the slot drops at task end.
//!
//! The slot is `tokio::task_local!`, so concurrent requests are
//! isolated by Tokio's per-task storage — no cross-tenant leakage.

use std::cell::RefCell;

thread_local! {
    static CANTON_JWT: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Guard that clears the task-local Canton JWT when dropped. Returned
/// by [`set_for_current_task`].
pub struct CantonJwtGuard;

impl Drop for CantonJwtGuard {
    fn drop(&mut self) {
        CANTON_JWT.with(|cell| {
            *cell.borrow_mut() = None;
        });
    }
}

/// Installs `jwt` into the current task's Canton JWT slot. The returned
/// guard clears the slot when dropped. Call sites typically bind the
/// guard to a `let _g = ...` at the top of the request handler.
pub fn set_for_current_task(jwt: String) -> CantonJwtGuard {
    CANTON_JWT.with(|cell| {
        *cell.borrow_mut() = Some(jwt);
    });
    CantonJwtGuard
}

/// Fetches the current task's Canton JWT, if any. Canton handlers
/// call this just before talking to the bridge adapter; the bridge
/// then uses `with_tenant_jwt` to scope the request to the tenant.
pub fn current() -> Option<String> {
    CANTON_JWT.with(|cell| cell.borrow().clone())
}
