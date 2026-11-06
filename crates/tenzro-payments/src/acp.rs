//! Agentic Commerce Protocol (ACP), seller side, API version
//! [`ACP_API_VERSION`].
//!
//! A node sells paid AI work to an agent that checks out over ACP:
//!
//! | Call | Method and path |
//! | --- | --- |
//! | create | `POST /checkout_sessions` |
//! | update | `POST /checkout_sessions/{id}` |
//! | get | `GET /checkout_sessions/{id}` |
//! | complete | `POST /checkout_sessions/{id}/complete` |
//! | cancel | `POST /checkout_sessions/{id}/cancel` |
//!
//! A line item's `item.id` names what is sold (for a serving node, a model)
//! and its `quantity` the units; the [`Seller`] prices it on its own rate
//! card. The session offers one payment handler, `tenzro`, whose `config`
//! carries the x402 payment requirement for the session total. The agent
//! completes with `payment_data.instrument.credential` set to an x402 payment
//! payload for that requirement, which the seller settles through its x402
//! facilitator: the payer's signature, its Terms and any AP2 mandates in the
//! payload's `extensions` are checked there, and the funds move on the
//! ledger. No card data is handled; a card instrument is refused.
//!
//! Every POST carries `Idempotency-Key`: a replay with the same body gets the
//! stored answer with `Idempotent-Replayed: true`, a replay with another body
//! is refused with 422.

use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use dashmap::DashMap;
use serde_json::{Value, json};

use crate::x402::{X402PaymentPayload, X402PaymentRequirement, X402SettlementResponse};

/// ACP API version this seller speaks.
pub const ACP_API_VERSION: &str = "2026-04-17";
/// The payment handler id a Tenzro payment completes under.
pub const TENZRO_HANDLER_ID: &str = "tenzro";
/// How long an open session stays payable.
pub const SESSION_TTL_SECS: i64 = 30 * 60;

/// What the node sells and how it is paid.
#[async_trait]
pub trait Seller: Send + Sync {
    /// The price of `quantity` units of `item_id`, in the asset's smallest
    /// unit, and the asset; `Err` with a reason when it is not for sale.
    fn price(&self, item_id: &str, quantity: u64) -> Result<(u128, String), String>;

    /// The x402 requirement an agent pays a session's `total` of `asset`
    /// against; `session_id` is the challenge it answers.
    fn requirement(&self, session_id: &str, total: u128, asset: &str) -> X402PaymentRequirement;

    /// Verify and settle `payload` against `requirement`.
    async fn settle(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
    ) -> X402SettlementResponse;
}

#[derive(Clone)]
struct Session {
    body: Value,
    total: u128,
    asset: String,
}

/// State behind the ACP router.
#[derive(Clone)]
pub struct AcpState {
    seller: Arc<dyn Seller>,
    sessions: Arc<DashMap<String, Session>>,
    /// Idempotency key to (request fingerprint, status, answer).
    replays: Arc<DashMap<String, (String, u16, Value)>>,
}

impl AcpState {
    /// State selling through `seller`.
    pub fn new(seller: Arc<dyn Seller>) -> Self {
        Self {
            seller,
            sessions: Arc::new(DashMap::new()),
            replays: Arc::new(DashMap::new()),
        }
    }
}

/// The ACP seller router.
pub fn acp_router(state: AcpState) -> Router {
    Router::new()
        .route("/checkout_sessions", post(create))
        .route("/checkout_sessions/:id", post(update).get(read))
        .route("/checkout_sessions/:id/complete", post(complete))
        .route("/checkout_sessions/:id/cancel", post(cancel))
        .with_state(state)
}

fn error(status: StatusCode, ty: &str, code: &str, message: impl Into<String>) -> Response {
    let mut body = json!({ "type": ty, "code": code, "message": message.into() });
    if code == "unsupported_api_version" {
        body["supported_versions"] = json!([ACP_API_VERSION]);
    }
    (status, Json(body)).into_response()
}

fn invalid(code: &str, message: impl Into<String>) -> Response {
    error(StatusCode::BAD_REQUEST, "invalid_request", code, message)
}

fn check_version(headers: &HeaderMap) -> Result<(), Response> {
    match headers.get("api-version").and_then(|v| v.to_str().ok()) {
        Some(ACP_API_VERSION) => Ok(()),
        Some(_) => Err(invalid(
            "unsupported_api_version",
            format!("this seller speaks API-Version {ACP_API_VERSION}"),
        )),
        None => Err(invalid("missing_api_version", "API-Version is required")),
    }
}

/// Run a POST once per `Idempotency-Key`.
async fn idempotent<F, Fut>(
    state: &AcpState,
    headers: &HeaderMap,
    route: &str,
    body: &Value,
    run: F,
) -> Response
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = (StatusCode, Value)>,
{
    if let Err(r) = check_version(headers) {
        return r;
    }
    let Some(key) = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .filter(|k| !k.is_empty() && k.len() <= 255)
    else {
        return invalid("missing_idempotency_key", "Idempotency-Key is required");
    };
    let fingerprint = format!("{route}\n{body}");
    let slot = format!("{route}\n{key}");
    if let Some(prior) = state.replays.get(&slot) {
        let (fp, status, answer) = prior.value().clone();
        if fp != fingerprint {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_request",
                "idempotency_conflict",
                "this Idempotency-Key was used with another request",
            );
        }
        let mut r = (
            StatusCode::from_u16(status).unwrap_or(StatusCode::OK),
            Json(answer),
        )
            .into_response();
        r.headers_mut()
            .insert("idempotent-replayed", HeaderValue::from_static("true"));
        return r;
    }
    let (status, answer) = run().await;
    if status.is_success() {
        state
            .replays
            .insert(slot, (fingerprint, status.as_u16(), answer.clone()));
    }
    (status, Json(answer)).into_response()
}

fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

/// Price `line_items` and build the session body.
fn priced(
    seller: &dyn Seller,
    id: &str,
    currency: &str,
    line_items: &Value,
    created_at: &str,
) -> Result<Session, (StatusCode, Value)> {
    let bad = |code: &str, msg: String| {
        (
            StatusCode::BAD_REQUEST,
            json!({"type": "invalid_request", "code": code, "message": msg, "param": "line_items"}),
        )
    };
    let items = line_items
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or_else(|| bad("invalid", "line_items must be a non-empty list".into()))?;
    let mut lines = Vec::new();
    let mut total: u128 = 0;
    let mut asset: Option<String> = None;
    for (i, li) in items.iter().enumerate() {
        let item_id = li
            .pointer("/item/id")
            .or_else(|| li.get("id"))
            .and_then(Value::as_str)
            .ok_or_else(|| bad("invalid", format!("line_items[{i}] names no item.id")))?;
        let quantity = li.get("quantity").and_then(Value::as_u64).unwrap_or(1);
        if quantity == 0 {
            return Err(bad("invalid", format!("line_items[{i}].quantity is 0")));
        }
        let (amount, a) = seller
            .price(item_id, quantity)
            .map_err(|m| bad("out_of_stock", format!("{item_id}: {m}")))?;
        match &asset {
            Some(prev) if !prev.eq_ignore_ascii_case(&a) => {
                return Err(bad(
                    "invalid",
                    "line items are priced in different assets".into(),
                ));
            }
            None => asset = Some(a.clone()),
            _ => {}
        }
        total = total
            .checked_add(amount)
            .ok_or_else(|| bad("invalid", "the total overflows".into()))?;
        lines.push(json!({
            "id": format!("li_{i}"),
            "item": { "id": item_id, "quantity": quantity },
            "quantity": quantity,
            "unit_amount": (amount / u128::from(quantity)).to_string(),
            "totals": [
                { "type": "items_base_amount", "display_text": "Base", "amount": amount.to_string() },
                { "type": "total", "display_text": "Total", "amount": amount.to_string() }
            ]
        }));
    }
    let asset = asset.unwrap_or_default();
    if !currency.eq_ignore_ascii_case(&asset) {
        return Err(bad(
            "invalid",
            format!("this seller prices in {asset}, not {currency}"),
        ));
    }
    let requirement = seller.requirement(id, total, &asset);
    let expires = now() + chrono::Duration::seconds(SESSION_TTL_SECS);
    let body = json!({
        "id": id,
        "status": "ready_for_payment",
        "currency": asset,
        "line_items": lines,
        "totals": [
            { "type": "subtotal", "display_text": "Subtotal", "amount": total.to_string() },
            { "type": "total", "display_text": "Total", "amount": total.to_string() }
        ],
        "fulfillment_options": [],
        "messages": [],
        "links": [],
        "capabilities": {
            "payment": {
                "handlers": [{
                    "id": TENZRO_HANDLER_ID,
                    "name": "Tenzro",
                    "version": crate::x402::X402_WIRE_VERSION.to_string(),
                    "spec": "https://github.com/x402-foundation/x402",
                    "requires_delegate_payment": false,
                    "requires_pci_compliance": false,
                    "psp": "tenzro",
                    "config_schema": {},
                    "instrument_schemas": [{
                        "type": "object",
                        "required": ["type", "credential"],
                        "properties": {
                            "type": { "const": "x402" },
                            "credential": { "description": "x402 PaymentPayload for config.requirement" }
                        }
                    }],
                    "config": { "requirement": requirement }
                }]
            }
        },
        "created_at": created_at,
        "updated_at": now().to_rfc3339(),
        "expires_at": expires.to_rfc3339(),
        "protocol": { "version": ACP_API_VERSION },
    });
    Ok(Session { body, total, asset })
}

fn live(state: &AcpState, id: &str) -> Result<Session, (StatusCode, Value)> {
    let s = state.sessions.get(id).map(|s| s.clone()).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            json!({"type": "invalid_request", "code": "not_found", "message": format!("no session {id}")}),
        )
    })?;
    let expired = s.body["expires_at"]
        .as_str()
        .and_then(|e| chrono::DateTime::parse_from_rfc3339(e).ok())
        .is_some_and(|e| now() >= e);
    let status = s.body["status"].as_str().unwrap_or_default();
    if status == "ready_for_payment" && expired {
        let mut s = s;
        s.body["status"] = json!("expired");
        state.sessions.insert(id.to_string(), s.clone());
        return Ok(s);
    }
    Ok(s)
}

fn open_for_change(s: &Session) -> Result<(), (StatusCode, Value)> {
    match s.body["status"].as_str() {
        Some("ready_for_payment") => Ok(()),
        other => Err((
            StatusCode::METHOD_NOT_ALLOWED,
            json!({"type": "invalid_request", "code": "invalid_state",
                   "message": format!("the session is {}", other.unwrap_or("unknown"))}),
        )),
    }
}

async fn create(
    State(state): State<AcpState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let st = state.clone();
    let fingerprint_body = body.clone();
    idempotent(
        &state,
        &headers,
        "create",
        &fingerprint_body,
        || async move {
            let currency = body
                .get("currency")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let id = format!("cs_{}", uuid::Uuid::new_v4().simple());
            match priced(
                st.seller.as_ref(),
                &id,
                currency,
                &body["line_items"],
                &now().to_rfc3339(),
            ) {
                Ok(s) => {
                    let out = s.body.clone();
                    st.sessions.insert(id, s);
                    (StatusCode::CREATED, out)
                }
                Err(e) => e,
            }
        },
    )
    .await
}

async fn update(
    State(state): State<AcpState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let st = state.clone();
    let route = format!("update/{id}");
    let fingerprint_body = body.clone();
    idempotent(&state, &headers, &route, &fingerprint_body, || async move {
        let s = match live(&st, &id) {
            Ok(s) => s,
            Err(e) => return e,
        };
        if let Err(e) = open_for_change(&s) {
            return e;
        }
        let Some(lines) = body.get("line_items") else {
            return (StatusCode::OK, s.body);
        };
        let created = s.body["created_at"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        match priced(st.seller.as_ref(), &id, &s.asset, lines, &created) {
            Ok(s) => {
                let out = s.body.clone();
                st.sessions.insert(id, s);
                (StatusCode::OK, out)
            }
            Err(e) => e,
        }
    })
    .await
}

async fn read(
    State(state): State<AcpState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = check_version(&headers) {
        return r;
    }
    match live(&state, &id) {
        Ok(s) => (StatusCode::OK, Json(s.body)).into_response(),
        Err((status, body)) => (status, Json(body)).into_response(),
    }
}

async fn complete(
    State(state): State<AcpState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let st = state.clone();
    let route = format!("complete/{id}");
    let fingerprint_body = body.clone();
    idempotent(&state, &headers, &route, &fingerprint_body, || async move {
        let s = match live(&st, &id) {
            Ok(s) => s,
            Err(e) => return e,
        };
        if let Err(e) = open_for_change(&s) {
            return e;
        }
        let pd = &body["payment_data"];
        let handler = pd.get("handler_id").and_then(Value::as_str).unwrap_or_default();
        if handler != TENZRO_HANDLER_ID {
            return (
                StatusCode::BAD_REQUEST,
                json!({"type": "invalid_request", "code": "payment_declined", "param": "payment_data.handler_id",
                       "message": format!("this seller completes only under the {TENZRO_HANDLER_ID} handler")}),
            );
        }
        if pd.pointer("/instrument/type").and_then(Value::as_str) != Some("x402") {
            return (
                StatusCode::BAD_REQUEST,
                json!({"type": "invalid_request", "code": "payment_declined", "param": "payment_data.instrument",
                       "message": "the tenzro handler takes an x402 instrument"}),
            );
        }
        let payload: X402PaymentPayload =
            match serde_json::from_value(pd.pointer("/instrument/credential").cloned().unwrap_or_default()) {
                Ok(p) => p,
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        json!({"type": "invalid_request", "code": "invalid", "param": "payment_data.instrument.credential",
                               "message": format!("not an x402 payment payload: {e}")}),
                    );
                }
            };
        let requirement = st.seller.requirement(&id, s.total, &s.asset);
        let settled = st.seller.settle(&requirement, &payload).await;
        if !settled.success {
            let mut failed = s.body.clone();
            failed["messages"] = json!([{
                "type": "error", "code": "payment_declined", "content_type": "plain",
                "content": settled.error_reason.clone().unwrap_or_else(|| "payment refused".into())
            }]);
            return (StatusCode::PAYMENT_REQUIRED, failed);
        }
        let mut done = s.clone();
        done.body["status"] = json!("completed");
        done.body["updated_at"] = json!(now().to_rfc3339());
        done.body["order"] = json!({
            "id": format!("ord_{}", id.trim_start_matches("cs_")),
            "checkout_session_id": id,
            "permalink_url": format!("tenzro:{}/{}", settled.network, settled.transaction),
            "payment": settled,
        });
        st.sessions.insert(id, done.clone());
        (StatusCode::OK, done.body)
    })
    .await
}

async fn cancel(
    State(state): State<AcpState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let st = state.clone();
    let route = format!("cancel/{id}");
    let fingerprint_body = body.clone();
    idempotent(&state, &headers, &route, &fingerprint_body, || async move {
        let s = match live(&st, &id) {
            Ok(s) => s,
            Err(e) => return e,
        };
        if let Err(e) = open_for_change(&s) {
            return e;
        }
        let mut c = s;
        c.body["status"] = json!("canceled");
        c.body["updated_at"] = json!(now().to_rfc3339());
        st.sessions.insert(id, c.clone());
        (StatusCode::OK, c.body)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use parking_lot::Mutex;
    use tower::ServiceExt;

    /// Sells `model-a` at 7 per unit in TNZO; settles payloads whose
    /// `payload.ok` is true.
    struct Shop(Mutex<Vec<String>>);

    #[async_trait]
    impl Seller for Shop {
        fn price(&self, item_id: &str, quantity: u64) -> Result<(u128, String), String> {
            match item_id {
                "model-a" => Ok((7 * u128::from(quantity), "TNZO".into())),
                _ => Err("not served here".into()),
            }
        }
        fn requirement(
            &self,
            session_id: &str,
            total: u128,
            asset: &str,
        ) -> X402PaymentRequirement {
            let mut r = X402PaymentRequirement::new(
                "tenzro-hybrid",
                "tenzro:1337",
                total.to_string(),
                "09".repeat(20),
                asset,
                60,
            );
            r.set_extra("challengeId", json!(session_id));
            r
        }
        async fn settle(
            &self,
            requirement: &X402PaymentRequirement,
            payload: &X402PaymentPayload,
        ) -> X402SettlementResponse {
            self.0.lock().push(requirement.amount.clone());
            if payload.payload["ok"] == true && payload.accepted == *requirement {
                X402SettlementResponse {
                    success: true,
                    error_reason: None,
                    payer: Some("0xpayer".into()),
                    transaction: "0xtx".into(),
                    network: requirement.network.clone(),
                    amount: Some(requirement.amount.clone()),
                    usage_record: None,
                    plan: None,
                }
            } else {
                X402SettlementResponse::failed(requirement.network.clone(), "invalid_payload")
            }
        }
    }

    async fn call(
        router: &Router,
        method: &str,
        path: &str,
        key: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, HeaderMap, Value) {
        let mut req = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", "Bearer t")
            .header("api-version", ACP_API_VERSION);
        if let Some(k) = key {
            req = req.header("idempotency-key", k);
        }
        let req = match body {
            Some(b) => req
                .header("content-type", "application/json")
                .body(Body::from(b.to_string())),
            None => req.body(Body::empty()),
        }
        .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let (status, headers) = (resp.status(), resp.headers().clone());
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            headers,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    fn create_body(units: u64) -> Value {
        json!({ "currency": "TNZO", "capabilities": {},
                "line_items": [{ "id": "x", "item": { "id": "model-a" }, "quantity": units }] })
    }

    fn payload_for(session: &Value, ok: bool) -> Value {
        let req = session
            .pointer("/capabilities/payment/handlers/0/config/requirement")
            .unwrap()
            .clone();
        json!({ "payment_data": { "handler_id": "tenzro",
            "instrument": { "type": "x402", "credential": {
                "x402Version": 2, "accepted": req, "payload": { "ok": ok } } } } })
    }

    #[tokio::test]
    async fn an_agent_checks_out_paid_work_and_pays_the_session_total() {
        let shop = Arc::new(Shop(Mutex::new(vec![])));
        let r = acp_router(AcpState::new(shop.clone()));
        let (st, _, s) = call(
            &r,
            "POST",
            "/checkout_sessions",
            Some("k1"),
            Some(create_body(3)),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        assert_eq!(s["status"], "ready_for_payment");
        assert_eq!(s["totals"][1]["type"], "total");
        assert_eq!(s["totals"][1]["amount"], "21");
        for field in [
            "id",
            "currency",
            "line_items",
            "fulfillment_options",
            "messages",
            "links",
            "capabilities",
        ] {
            assert!(s.get(field).is_some(), "{field}");
        }
        let id = s["id"].as_str().unwrap().to_string();

        // Update to 5 units: the requirement follows the new total.
        let (_, _, s) = call(
            &r,
            "POST",
            &format!("/checkout_sessions/{id}"),
            Some("k2"),
            Some(json!({ "line_items": [{ "item": { "id": "model-a" }, "quantity": 5 }] })),
        )
        .await;
        assert_eq!(s["totals"][1]["amount"], "35");

        // A payment that does not settle leaves the session payable.
        let (st, _, _) = call(
            &r,
            "POST",
            &format!("/checkout_sessions/{id}/complete"),
            Some("k3"),
            Some(payload_for(&s, false)),
        )
        .await;
        assert_eq!(st, StatusCode::PAYMENT_REQUIRED);

        let (st, _, done) = call(
            &r,
            "POST",
            &format!("/checkout_sessions/{id}/complete"),
            Some("k4"),
            Some(payload_for(&s, true)),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(done["status"], "completed");
        assert_eq!(done["order"]["checkout_session_id"], id);
        assert_eq!(done["order"]["payment"]["transaction"], "0xtx");
        assert_eq!(
            shop.0.lock().clone(),
            vec!["35".to_string(), "35".to_string()]
        );

        // A replayed complete is answered from the record, not paid twice.
        let (st, h, again) = call(
            &r,
            "POST",
            &format!("/checkout_sessions/{id}/complete"),
            Some("k4"),
            Some(payload_for(&s, true)),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(h["idempotent-replayed"], "true");
        assert_eq!(again["order"]["id"], done["order"]["id"]);
        assert_eq!(shop.0.lock().len(), 2);

        // A completed session cannot be paid again under a new key, or canceled.
        let (st, _, _) = call(
            &r,
            "POST",
            &format!("/checkout_sessions/{id}/complete"),
            Some("k5"),
            Some(payload_for(&s, true)),
        )
        .await;
        assert_eq!(st, StatusCode::METHOD_NOT_ALLOWED);
        let (st, _, _) = call(
            &r,
            "POST",
            &format!("/checkout_sessions/{id}/cancel"),
            Some("k6"),
            Some(json!({})),
        )
        .await;
        assert_eq!(st, StatusCode::METHOD_NOT_ALLOWED);
        let (_, _, got) = call(&r, "GET", &format!("/checkout_sessions/{id}"), None, None).await;
        assert_eq!(got["status"], "completed");
    }

    #[tokio::test]
    async fn the_headers_the_spec_requires_are_enforced() {
        let r = acp_router(AcpState::new(Arc::new(Shop(Mutex::new(vec![])))));
        let (st, _, e) = call(&r, "POST", "/checkout_sessions", None, Some(create_body(1))).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert_eq!(e["code"], "missing_idempotency_key");

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/checkout_sessions")
            .header("api-version", "2025-09-29")
            .header("idempotency-key", "a")
            .header("content-type", "application/json")
            .body(Body::from(create_body(1).to_string()))
            .unwrap();
        let resp = r.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let e: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(e["supported_versions"][0], ACP_API_VERSION);

        // The same key with another body is a conflict.
        call(
            &r,
            "POST",
            "/checkout_sessions",
            Some("same"),
            Some(create_body(1)),
        )
        .await;
        let (st, _, _) = call(
            &r,
            "POST",
            "/checkout_sessions",
            Some("same"),
            Some(create_body(2)),
        )
        .await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn unpriced_work_and_card_instruments_are_refused() {
        let r = acp_router(AcpState::new(Arc::new(Shop(Mutex::new(vec![])))));
        let body = json!({ "currency": "TNZO", "capabilities": {},
                           "line_items": [{ "item": { "id": "model-z" }, "quantity": 1 }] });
        let (st, _, _) = call(&r, "POST", "/checkout_sessions", Some("a"), Some(body)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let usd = json!({ "currency": "USD", "capabilities": {},
                          "line_items": [{ "item": { "id": "model-a" }, "quantity": 1 }] });
        let (st, _, _) = call(&r, "POST", "/checkout_sessions", Some("b"), Some(usd)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        let (_, _, s) = call(
            &r,
            "POST",
            "/checkout_sessions",
            Some("c"),
            Some(create_body(1)),
        )
        .await;
        let id = s["id"].as_str().unwrap();
        let card = json!({ "payment_data": { "handler_id": "card",
                           "instrument": { "type": "card", "credential": { "token": "spt_x" } } } });
        let (st, _, e) = call(
            &r,
            "POST",
            &format!("/checkout_sessions/{id}/complete"),
            Some("d"),
            Some(card),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert_eq!(e["code"], "payment_declined");
    }
}
