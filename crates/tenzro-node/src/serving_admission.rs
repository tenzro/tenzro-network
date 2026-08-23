//! One admission decision for every inference entry point.
//!
//! The node has three independent bounds — [`TrafficManager`] (can we finish
//! this in time?), [`ModelLifecycle`] (is the model loaded?), and
//! [`MemoryBudget`](tenzro_model::memory_budget) (does it fit?). Handlers
//! must not consult them individually: a handler that checks two of three is
//! a hole, and there are dozens of handlers.
//!
//! [`admit_inference`] is the single call. It returns one of three answers,
//! and every caller maps those three onto its own wire format.
//!
//! # Callers wait for their answer; they are not sent away to retry
//!
//! A frontier API does not tell a user "the model is loading, come back in
//! twenty seconds". It accepts the request and returns the result. The user
//! never learns whether they queued, and that is the point — a queue the user
//! can feel is a queue that feels broken.
//!
//! So [`admit_inference`] **waits** for a cold model to warm, up to the
//! request's own deadline, and only then serves. The load itself still runs
//! as a detached task, because the caller's socket must not be what drives
//! it: two callers for the same cold model join one load rather than starting
//! two.
//!
//! Waiting does not hold a concurrency slot. The traffic guard is taken only
//! once the model is actually ready, so a hundred callers waiting on a load
//! do not occupy the capacity the node needs to serve them the moment it
//! finishes.
//!
//! [`Decision::Warming`] is therefore the *exceptional* answer, not the
//! normal one — it means the wait would exceed the caller's deadline, so the
//! honest reply is "not in the time you asked for" rather than a stall. Even
//! then it carries an estimate and a retry hint, so a client that wants to
//! wait longer can.
//!
//! # Eviction is part of loading
//!
//! A cold model can only warm if there is room. When the budget refuses, the
//! warm task evicts least-recently-used models until the new one fits, or
//! gives up if nothing is evictable — everything either pinned or serving. A
//! failed warm returns the model to cold so the next caller can retry, rather
//! than leaving it stuck in `Warming` forever with callers waiting on a load
//! that is not running.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tenzro_model::lifecycle::{Admission, InFlightGuard, WarmingStatus};
use tenzro_model::memory_budget::{MemoryBudget, Tier};
use tenzro_model::traffic::{QosClass, Refusal, RequestGuard};
use tracing::{debug, info, warn};

use crate::node::TenzroNode;

/// Held for the life of an admitted request.
///
/// Both guards release on drop, so a handler that returns early or panics
/// cannot leak a concurrency slot or pin a model against eviction. Field
/// order matters on drop only in that both must run; neither depends on the
/// other.
#[derive(Debug)]
pub struct ServingPermit {
    _traffic: RequestGuard,
    _model: InFlightGuard,
    /// The per-model concurrency slot. Held here so the four bounds are
    /// acquired and released as one unit rather than by separate call sites
    /// that can disagree about whether a request ran.
    _load: tenzro_model::LoadGuard,
}

/// What a handler should do with this request.
#[derive(Debug)]
pub enum Decision {
    /// Serve it. Hold the permit until the response is complete — including
    /// through streaming, or the model can be evicted mid-stream.
    Proceed(Box<ServingPermit>),
    /// The model is loading. Tell the caller when to come back.
    Warming(WarmingStatus),
    /// The node cannot take this request now.
    Refused(Refusal),
}

/// Decide whether to serve `model_id` now, warming it if necessary.
///
/// `queue_ahead` is how many requests are already waiting on this model; it
/// converts a per-request cost estimate into a completion-time prediction.
/// Pass 0 when the depth is not known — the prediction then reflects an
/// unloaded queue, which is the optimistic case.
///
/// Order is deliberate. Traffic admission runs **first**: it is the cheapest
/// check and the one protecting the machine, so an overloaded node refuses
/// before it does any lifecycle bookkeeping or starts a load it has no
/// capacity to serve from.
pub async fn admit_inference(
    node: &Arc<TenzroNode>,
    model_id: &str,
    class: QosClass,
    deadline: Option<Duration>,
    queue_ahead: u32,
    est_tokens: u64,
) -> Decision {
    // Two different budgets, because they answer two different questions.
    //
    // The QoS deadline is a *serving* SLO: how long an interactive caller is
    // willing to wait for a model that is up. A cold load is not serving, and
    // 30s of it never covered a 22 GB GGUF, so every first request after a
    // restart was refused with "retry in about 70000 ms" — a dead end that
    // told the caller to come back without accepting any work.
    //
    // The warm budget is how long a caller will wait for the load itself.
    // Waiting through it and then answering is strictly better than refusing:
    // the caller asked for an answer, not for a schedule. Operator-tunable
    // because it depends on the largest model a node holds, and set to zero
    // by a caller that genuinely wants the old fail-fast behaviour.
    let serving_budget = deadline.unwrap_or_else(|| class.default_deadline());
    let warm_budget = warm_wait_budget().max(serving_budget);
    let budget = warm_budget;
    let started = Instant::now();

    loop {
        // Reconcile with the runtime before deciding. Models also reach memory
        // via explicit serve calls and the holder's lazy load; without this a
        // resident model reads as cold and the caller waits for a load that
        // already happened.
        if let Some(runtime) = node.model_runtime_arc()
            && runtime.is_loaded(model_id)
        {
            node.lifecycle().adopt_if_loaded(model_id);
        }

        let warming_status = match node.lifecycle().admit(model_id) {
            Admission::Ready(model_guard) => {
                // Only now take a concurrency slot. Taking it before the wait
                // would have a hundred queued callers occupying the capacity
                // needed to serve them.
                let remaining = serving_budget.saturating_sub(started.elapsed());
                let traffic_guard =
                    match node
                        .traffic()
                        .admit(model_id, class, Some(remaining), queue_ahead, est_tokens)
                    {
                        Ok(g) => g,
                        Err(refusal) => return Decision::Refused(refusal),
                    };

                // The per-model cap, acquired here rather than by the handler.
                //
                // Acquiring it separately downstream was a real bug found in
                // bring-up: this layer admitted, the per-model cap refused,
                // and the traffic guard dropped as a *completion* — so
                // goodput reported 100% while most requests failed. A bound
                // that can refuse must be part of the same decision, and a
                // request that never ran must not be counted as one that did.
                let Ok(load_guard) = node.load_tracker.try_acquire(model_id) else {
                    let snapshot = node.load_tracker.snapshot(model_id);
                    let (active, limit) = snapshot
                        .map(|s| (s.active_requests, s.max_concurrent))
                        .unwrap_or((0, 0));
                    traffic_guard.abort();
                    return Decision::Refused(Refusal::AtCapacity {
                        in_flight: active,
                        limit,
                        retry_after_ms: 1_000,
                    });
                };

                return Decision::Proceed(Box::new(ServingPermit {
                    _traffic: traffic_guard,
                    _model: model_guard,
                    _load: load_guard,
                }));
            }
            Admission::Warming(status) => status,
            Admission::LoadRequired(status) => {
                // Elected to load. The load runs detached so that this
                // caller's socket is not what drives it — otherwise a client
                // disconnect would abandon a load other callers are waiting
                // on.
                spawn_warm(Arc::clone(node), model_id.to_string());
                status
            }
        };

        // Would the wait outlast what the caller asked for? Then say so
        // rather than stall them to their own timeout, which teaches clients
        // nothing and looks identical to a hang.
        let elapsed = started.elapsed();
        let remaining = budget.saturating_sub(elapsed);
        if Duration::from_millis(warming_status.estimated_ready_ms) > remaining {
            debug!(
                model_id = %model_id,
                estimated_ready_ms = warming_status.estimated_ready_ms,
                remaining_ms = remaining.as_millis() as u64,
                "warm would outlast the request deadline; returning warming status"
            );
            return Decision::Warming(warming_status);
        }

        tokio::time::sleep(WARM_POLL_INTERVAL.min(remaining)).await;

        // Deadline spent while waiting. Report the current estimate so the
        // caller can decide whether to come back with a longer one.
        if started.elapsed() >= budget {
            return Decision::Warming(warming_status);
        }
    }
}

/// How long a caller waits for a model to finish loading before being told to
/// come back, from `TENZRO_WARM_WAIT_SECS`.
///
/// Defaults to five minutes: enough for the largest GGUF in the catalog to
/// page in on a cold cache, so a restart costs the first caller latency rather
/// than an error. Set it to `0` to restore fail-fast admission.
fn warm_wait_budget() -> Duration {
    std::env::var("TENZRO_WARM_WAIT_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(300))
}

/// How often the wait loop re-checks whether a warming model is ready.
///
/// Short enough that a caller is served promptly after the load lands —
/// waiting out a full second on a model that became ready immediately is
/// latency nobody needs — and long enough that a hundred waiters do not spin
/// the lock. The poll is a lock read, not work, so this is cheap.
const WARM_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Load `model_id` in the background, evicting to make room if needed.
fn spawn_warm(node: Arc<TenzroNode>, model_id: String) {
    tokio::spawn(async move {
        let started = Instant::now();
        match warm_model(&node, &model_id).await {
            Ok(()) => {
                node.lifecycle().finish_warm(&model_id, started.elapsed());
                info!(
                    model_id = %model_id,
                    took_ms = started.elapsed().as_millis() as u64,
                    "Model warmed"
                );
            }
            Err(e) => {
                // Back to cold, so the next caller may retry. Leaving it
                // Warming would park every subsequent request on a load that
                // is not happening.
                node.lifecycle().abandon_warm(&model_id);
                warn!(model_id = %model_id, error = %e, "Model warm failed; returned to cold");
            }
        }
    });
}

/// Resolve, admit, and load one model.
async fn warm_model(node: &Arc<TenzroNode>, model_id: &str) -> Result<(), String> {
    let runtime = node
        .model_runtime_arc()
        .ok_or_else(|| "model runtime not initialized".to_string())?;

    let gguf_path = node
        .resolve_gguf_path(model_id)
        .ok_or_else(|| format!("{model_id} is not downloaded on this node"))?;

    let file_len = std::fs::metadata(&gguf_path)
        .map_err(|e| format!("cannot stat {}: {e}", gguf_path.display()))?
        .len();
    let needed = MemoryBudget::with_headroom(file_len);

    make_room_for(node, &runtime, model_id, needed).await?;

    let context_length = tenzro_model::get_model_by_id(model_id).map(|e| e.context_length);
    runtime
        .load_model_with_context(model_id, &gguf_path, context_length)
        .await
        .map_err(|e| format!("load failed: {e}"))
}

/// Evict least-recently-used models until `needed` bytes are free in the
/// resident tier.
///
/// Returns an error when the tier cannot be made to fit — either the model is
/// larger than the whole tier, or everything resident is pinned or serving.
/// Both are refusals rather than something to retry blindly, and the message
/// distinguishes them because the operator responses differ.
async fn make_room_for(
    node: &Arc<TenzroNode>,
    runtime: &Arc<tenzro_model::ModelRuntime>,
    model_id: &str,
    needed: u64,
) -> Result<(), String> {
    let budget = tenzro_model::memory_budget::global();

    // Bounded: each iteration evicts one model, and there are finitely many.
    loop {
        if budget.would_admit(Tier::Resident, needed) {
            return Ok(());
        }

        let Some(victim) = node.lifecycle().evict_candidate() else {
            return Err(format!(
                "cannot free {:.1} GiB for {model_id}: every resident model is pinned or \
                 serving a request",
                needed as f64 / 1_073_741_824.0
            ));
        };

        // begin_evict re-checks under its own lock: a model that started
        // serving between the candidate scan and here must not be torn down.
        if !node.lifecycle().begin_evict(&victim) {
            debug!(victim = %victim, "eviction candidate became busy; re-scanning");
            continue;
        }

        match runtime.unload_model(&victim).await {
            Ok(()) => {
                node.lifecycle().finish_evict(&victim);
                info!(
                    evicted = %victim,
                    for_model = %model_id,
                    "Evicted least-recently-used model to make room"
                );
            }
            Err(e) => {
                // The model is still resident, so it must go back to warm
                // rather than be recorded as evicted — otherwise the budget
                // and reality diverge permanently.
                node.lifecycle().finish_warm(&victim, Duration::ZERO);
                return Err(format!("failed to evict {victim}: {e}"));
            }
        }
    }
}

/// JSON-RPC error for a model that is still loading.
///
/// Uses `-32005` with `retry_after_ms`, matching the convention already used
/// by the rate-limit gate, so one SDK backoff path covers both. The JSON-RPC
/// envelope carries no HTTP status, so the retry hint has to live in `data`.
pub(crate) fn warming_rpc_error(status: &WarmingStatus) -> crate::rpc::JsonRpcError {
    crate::rpc::JsonRpcError {
        code: -32005,
        message: format!(
            "model '{}' is loading; retry in about {} ms",
            status.model, status.estimated_ready_ms
        ),
        data: Some(serde_json::json!({
            "status": status.status,
            "model": status.model,
            "estimated_ready_ms": status.estimated_ready_ms,
            "retry_after_ms": status.retry_after_ms,
            "waiters": status.waiters,
        })),
    }
}

/// JSON-RPC error for a refused request.
pub(crate) fn refusal_rpc_error(refusal: &Refusal) -> crate::rpc::JsonRpcError {
    crate::rpc::JsonRpcError {
        code: -32005,
        message: refusal.message(),
        data: Some(serde_json::json!({
            "status": "refused",
            "retry_after_ms": refusal.retry_after_ms(),
            "detail": refusal,
        })),
    }
}

/// HTTP response for a model that is still loading.
///
/// 503 with `Retry-After` is the standard shape for "temporarily unavailable,
/// come back": clients and proxies already understand it, where a bespoke
/// status would need explaining to every SDK author.
pub fn warming_http_response(status: &WarmingStatus) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        [(
            axum::http::header::RETRY_AFTER,
            status.retry_after_secs().to_string(),
        )],
        axum::Json(serde_json::json!({
            "error": {
                "type": "model_warming",
                "message": format!(
                    "model '{}' is loading; retry in about {} ms",
                    status.model, status.estimated_ready_ms
                ),
                "status": status.status,
                "model": status.model,
                "estimated_ready_ms": status.estimated_ready_ms,
                "retry_after_ms": status.retry_after_ms,
                "waiters": status.waiters,
            }
        })),
    )
        .into_response()
}

/// HTTP response for a refused request.
///
/// 429 rather than 503: the node is working, this caller is being asked to
/// slow down. The distinction matters to clients, which commonly retry 503
/// and back off on 429.
pub fn refusal_http_response(refusal: &Refusal) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        [(
            axum::http::header::RETRY_AFTER,
            refusal.retry_after_secs().to_string(),
        )],
        axum::Json(serde_json::json!({
            "error": {
                "type": "capacity",
                "message": refusal.message(),
                "retry_after_ms": refusal.retry_after_ms(),
                "detail": refusal,
            }
        })),
    )
        .into_response()
}

/// Default QoS class for a request.
///
/// Bulk work declares itself by asking for many inputs at once; a chat turn
/// or a single embedding is someone waiting. Getting this wrong in the safe
/// direction (treating batch as interactive) only costs a little reserved
/// capacity, so the threshold is deliberately high.
pub fn classify(batch_size: usize) -> QosClass {
    if batch_size > 8 {
        QosClass::Batch
    } else {
        QosClass::Interactive
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wait loop's decision rule, lifted out so it can be tested without
    /// standing up a node. Returns whether a caller should keep waiting.
    ///
    /// This is the judgement the whole queueing design rests on: wait when the
    /// model will be ready inside the caller's budget, refuse when it will
    /// not. Getting it wrong in one direction stalls users to their own
    /// timeout; in the other, it sends away callers who would have been served
    /// comfortably in time.
    fn should_keep_waiting(estimated_ready_ms: u64, remaining: Duration) -> bool {
        Duration::from_millis(estimated_ready_ms) <= remaining
    }

    #[test]
    fn a_caller_waits_when_the_model_lands_inside_their_budget() {
        // The normal case, and the one users never notice: a 20s load against
        // a 30s deadline is a wait, not a refusal.
        assert!(should_keep_waiting(20_000, Duration::from_secs(30)));
        assert!(should_keep_waiting(1_000, Duration::from_secs(30)));
    }

    #[test]
    fn a_caller_is_told_when_the_wait_would_outlast_their_deadline() {
        // Stalling them to their own timeout teaches the client nothing and
        // is indistinguishable from a hang.
        assert!(!should_keep_waiting(45_000, Duration::from_secs(30)));
        assert!(!should_keep_waiting(1_000, Duration::from_millis(999)));
    }

    #[test]
    fn an_exactly_fitting_wait_is_still_a_wait() {
        // Boundary: refusing a load that lands precisely on the deadline would
        // shed work the node could have completed.
        assert!(should_keep_waiting(30_000, Duration::from_secs(30)));
    }

    #[test]
    fn the_poll_interval_is_short_enough_not_to_add_visible_latency() {
        // A caller served the moment the load lands should not then sit out a
        // long poll. 100ms is below the threshold a user perceives as a stall.
        assert!(WARM_POLL_INTERVAL <= Duration::from_millis(250));
        assert!(
            WARM_POLL_INTERVAL >= Duration::from_millis(10),
            "too tight and many waiters spin the lifecycle lock"
        );
    }

    #[test]
    fn batch_work_gets_a_far_longer_budget_than_interactive() {
        // A bulk embedding job should tolerate a cold start that an
        // interactive turn should not.
        assert!(QosClass::Batch.default_deadline() > QosClass::Interactive.default_deadline());
        assert!(should_keep_waiting(
            120_000,
            QosClass::Batch.default_deadline()
        ));
        assert!(!should_keep_waiting(
            120_000,
            QosClass::Interactive.default_deadline()
        ));
    }

    #[test]
    fn a_single_input_is_interactive_and_a_bulk_job_is_batch() {
        assert_eq!(classify(1), QosClass::Interactive);
        assert_eq!(classify(8), QosClass::Interactive);
        assert_eq!(classify(9), QosClass::Batch);
        assert_eq!(classify(10_000), QosClass::Batch);
    }

    #[test]
    fn a_warming_response_carries_a_retry_after_header_a_proxy_understands() {
        let status = WarmingStatus {
            status: "warming",
            model: "qwen3.6-35b-a3b".to_string(),
            estimated_ready_ms: 30_000,
            retry_after_ms: 37_500,
            waiters: 3,
        };
        let response = warming_http_response(&status);
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        let retry = response
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .expect("Retry-After must be present");
        assert_eq!(retry.to_str().unwrap(), "38", "37.5s rounds up, never down");
    }

    #[test]
    fn a_refusal_is_429_not_503() {
        // 503 says the node is unavailable; 429 says it is working and this
        // caller should slow down. Clients treat them differently.
        let refusal = Refusal::AtCapacity {
            in_flight: 40,
            limit: 40,
            retry_after_ms: 1_000,
        };
        let response = refusal_http_response(&refusal);
        assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .unwrap()
                .to_str()
                .unwrap(),
            "1"
        );
    }

    #[test]
    fn rpc_errors_carry_a_machine_readable_retry_hint() {
        // The JSON-RPC envelope has no HTTP status, so the hint has to be in
        // `data` or an SDK cannot back off correctly.
        let status = WarmingStatus {
            status: "warming",
            model: "m".to_string(),
            estimated_ready_ms: 5_000,
            retry_after_ms: 6_250,
            waiters: 1,
        };
        let err = warming_rpc_error(&status);
        assert_eq!(err.code, -32005);
        let data = err.data.expect("data must be present");
        assert_eq!(data["retry_after_ms"], 6_250);
        assert_eq!(data["status"], "warming");

        let refusal = Refusal::ShedForInteractive {
            retry_after_ms: 5_000,
        };
        let err = refusal_rpc_error(&refusal);
        assert_eq!(err.code, -32005);
        assert_eq!(err.data.expect("data")["retry_after_ms"], 5_000);
    }

    #[test]
    fn retry_after_never_rounds_down_to_zero() {
        // A sub-second hint rounding to "0" produces a hot retry loop exactly
        // when the node is most loaded.
        let refusal = Refusal::DeadlineUnattainable {
            predicted_ms: 10,
            deadline_ms: 5,
            retry_after_ms: 100,
        };
        let response = refusal_http_response(&refusal);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .unwrap()
                .to_str()
                .unwrap(),
            "1"
        );
    }
}
