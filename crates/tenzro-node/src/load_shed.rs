//! Admission at the edge of the public listeners: the node refuses work it
//! has no capacity for, with a clear 503 and a Retry-After, instead of
//! queueing it behind consensus.
//!
//! Every request is classified into a [`WorkClass`] from its path. The gate
//! counts requests in flight per class and refuses a new one when the class
//! is at the share of its normal limit the current [`LoadLevel`] allows
//! ([`capacity_percent`]). The refusal is immediate and cheap (two atomic
//! operations), so it holds under a flood that would otherwise fill the
//! queue of a concurrency limiter. Health and access paths are never refused.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;

use crate::load_monitor::{LoadLevel, WorkClass, capacity_percent, current_level};

/// JSON-RPC error code of a request refused for load.
pub const RPC_ERR_OVERLOADED: i32 = -32003;

/// Paths that are always served: the checks a proxy and an operator use to
/// see that the node is alive, and the loopback admin page.
const EXEMPT: &[&str] = &[
    "/health", "/healthz", "/ready", "/metrics", "/status", "/load",
];

/// Requests allowed in flight per class at GREEN. These sit above the
/// listener's own concurrency limit, so at GREEN they only bound the queue
/// behind it.
const BASE: [usize; 7] = [usize::MAX, usize::MAX, 2000, 2000, 256, 256, 64];

/// The class a request belongs to.
pub fn classify(path: &str) -> WorkClass {
    if tenzro_payments::middleware::INFERENCE_ROUTES.contains(&path)
        || path.starts_with("/v1/images")
        || path.starts_with("/v1/audio")
        || path.starts_with("/v1/chat")
        || path.starts_with("/v1/responses")
        || path.starts_with("/tenzro/media")
    {
        WorkClass::ModelServing
    } else if path.starts_with("/relay") || path.starts_with("/v1/relay") {
        WorkClass::RelayAndProvider
    } else {
        WorkClass::PublicRpc
    }
}

/// A JSON-RPC call refused for load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodRefusal {
    /// What to tell the caller.
    pub message: String,
    /// The level that caused it.
    pub level: LoadLevel,
    /// Seconds to wait before retrying.
    pub retry_after: u64,
}

/// The class of a JSON-RPC method, when it is one of the shed classes.
pub fn method_class(method: &str) -> Option<WorkClass> {
    let m = method.strip_prefix("tenzro_").unwrap_or(method);
    if m.starts_with("chat")
        || m.starts_with("infer")
        || m.starts_with("generate")
        || m.starts_with("embed")
        || m.starts_with("transcribe")
        || m.starts_with("mediaGen")
        || m.starts_with("load")
    {
        Some(WorkClass::ModelServing)
    } else {
        None
    }
}

/// Whether a method is refused now: model work is refused when its class is
/// paused, and loading a model is refused while the memory guard holds.
pub fn method_refusal(method: &str) -> Option<MethodRefusal> {
    let level = current_level();
    let class = method_class(method)?;
    let heavy = method
        .strip_prefix("tenzro_")
        .unwrap_or(method)
        .starts_with("load");
    let paused = capacity_percent(class, level) == 0;
    if paused || (heavy && crate::load_monitor::refuses_memory_heavy()) {
        let why = if paused { class.name() } else { "memory-heavy" };
        let retry_after = level.retry_after_secs();
        return Some(MethodRefusal {
            message: format!(
                "the node is under load ({}) and is not taking {} requests now; retry in {} seconds",
                level.name(),
                why,
                retry_after
            ),
            level,
            retry_after,
        });
    }
    None
}

/// Requests in flight per class.
#[derive(Debug, Default)]
pub struct ShedGate {
    in_flight: [AtomicUsize; 7],
}

/// Holds a slot in a class until dropped.
pub struct Slot<'a> {
    gate: &'a ShedGate,
    class: WorkClass,
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.gate.in_flight[self.class as usize].fetch_sub(1, Ordering::AcqRel);
    }
}

impl ShedGate {
    /// A gate with nothing in flight.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The most requests of `class` allowed in flight at `level`.
    pub fn limit(class: WorkClass, level: LoadLevel) -> usize {
        let cap = capacity_percent(class, level) as usize;
        match (cap, BASE[class as usize]) {
            (0, _) => 0,
            (100, b) => b,
            (c, b) => (b / 100 * c).max(1),
        }
    }

    /// Takes a slot for `class` at `level`, or says how long to wait.
    pub fn enter(&self, class: WorkClass, level: LoadLevel) -> Result<Slot<'_>, u64> {
        let limit = Self::limit(class, level);
        let n = self.in_flight[class as usize].fetch_add(1, Ordering::AcqRel);
        if n >= limit {
            self.in_flight[class as usize].fetch_sub(1, Ordering::AcqRel);
            return Err(level.retry_after_secs());
        }
        Ok(Slot { gate: self, class })
    }

    /// Requests of `class` in flight now.
    pub fn in_flight(&self, class: WorkClass) -> usize {
        self.in_flight[class as usize].load(Ordering::Acquire)
    }
}

/// The 503 a shed request gets.
pub fn refusal(class: WorkClass, level: LoadLevel, retry_after: u64, jsonrpc: bool) -> Response {
    let message = format!(
        "the node is under load ({}) and is not taking {} requests now; retry in {} seconds",
        level.name(),
        class.name(),
        retry_after
    );
    let body = if jsonrpc {
        serde_json::json!({
            "jsonrpc": "2.0",
            "error": {"code": RPC_ERR_OVERLOADED, "message": message,
                      "data": {"load": level.name(), "retry_after": retry_after}},
            "id": null,
        })
    } else {
        serde_json::json!({
            "error": {"type": "overloaded", "message": message,
                      "load": level.name(), "retry_after": retry_after},
        })
    };
    let mut res = Response::new(axum::body::Body::from(body.to_string()));
    *res.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    res.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(retry_after));
    res
}

/// Axum middleware: refuses a request of a shed class with 503 and
/// Retry-After, and counts the rest.
pub async fn load_shed(State(gate): State<Arc<ShedGate>>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    if EXEMPT.contains(&path.as_str()) || path.starts_with("/access") {
        return next.run(req).await;
    }
    let level = current_level();
    let class = classify(&path);
    match gate.enter(class, level) {
        Ok(_slot) => next.run(req).await,
        Err(after) => refusal(class, level, after, path == "/"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inference_paths_are_model_serving_and_the_root_is_public() {
        assert_eq!(classify("/v1/chat/completions"), WorkClass::ModelServing);
        assert_eq!(classify("/v1/embeddings"), WorkClass::ModelServing);
        assert_eq!(classify("/"), WorkClass::PublicRpc);
        assert_eq!(classify("/v1/blocks/3"), WorkClass::PublicRpc);
    }

    #[test]
    fn limits_follow_the_capacity_table() {
        assert_eq!(
            ShedGate::limit(WorkClass::PublicRpc, LoadLevel::Green),
            2000
        );
        assert_eq!(
            ShedGate::limit(WorkClass::PublicRpc, LoadLevel::Elevated),
            1500
        );
        assert_eq!(ShedGate::limit(WorkClass::PublicRpc, LoadLevel::High), 800);
        assert_eq!(
            ShedGate::limit(WorkClass::PublicRpc, LoadLevel::Critical),
            200
        );
        assert_eq!(
            ShedGate::limit(WorkClass::ModelServing, LoadLevel::Critical),
            0
        );
        assert_eq!(
            ShedGate::limit(WorkClass::ConsensusAndCustody, LoadLevel::Critical),
            usize::MAX
        );
    }

    #[test]
    fn a_paused_class_is_refused_and_a_slot_is_returned_on_drop() {
        let g = ShedGate::new();
        assert_eq!(
            g.enter(WorkClass::ModelServing, LoadLevel::Critical).err(),
            Some(10)
        );
        assert_eq!(g.in_flight(WorkClass::ModelServing), 0);
        let slot = g.enter(WorkClass::PublicRpc, LoadLevel::Critical).unwrap();
        assert_eq!(g.in_flight(WorkClass::PublicRpc), 1);
        drop(slot);
        assert_eq!(g.in_flight(WorkClass::PublicRpc), 0);
    }

    #[test]
    fn the_limit_is_enforced_per_class() {
        let g = ShedGate::new();
        let held: Vec<_> = (0..200)
            .map(|_| g.enter(WorkClass::PublicRpc, LoadLevel::Critical).unwrap())
            .collect();
        assert!(g.enter(WorkClass::PublicRpc, LoadLevel::Critical).is_err());
        // Another class is not affected.
        assert!(
            g.enter(WorkClass::TransactionAdmission, LoadLevel::Critical)
                .is_ok()
        );
        drop(held);
    }

    #[test]
    fn the_refusal_is_503_with_retry_after() {
        let r = refusal(WorkClass::PublicRpc, LoadLevel::High, 5, true);
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(r.headers().get(header::RETRY_AFTER).unwrap(), "5");
    }
}
