//! Universal Commerce Protocol (UCP) checkout, business side, version
//! [`UCP_VERSION`] (<https://ucp.dev/2026-08-25/specification/overview/>,
//! schemas from <https://github.com/Universal-Commerce-Protocol/ucp> at tag
//! `v2026-08-25`), REST transport, with the AP2 mandates extension
//! (`dev.ucp.common.payment.ap2_mandate`) required and one payment handler,
//! `dev.tenzro.x402`.
//!
//! | Operation | Method and path |
//! | --- | --- |
//! | profile | `GET /.well-known/ucp` |
//! | create | `POST /checkout-sessions` |
//! | get | `GET /checkout-sessions/{id}` |
//! | update | `PUT /checkout-sessions/{id}` |
//! | complete | `POST /checkout-sessions/{id}/complete` |
//! | cancel | `POST /checkout-sessions/{id}/cancel` |
//!
//! Every request carries `UCP-Agent` and `Request-Id`; every POST and PUT
//! carries `Idempotency-Key`, and a key reused with another body is refused
//! with 409.
//!
//! A checkout is the session the ACP seller ([`crate::acp`]) keeps, priced by
//! the same [`Seller`](crate::acp::Seller). Amounts are integers in nano-TNZO
//! (the handler's `config.amount_scale` is 9: one unit is 10^9 base units),
//! rounded up; the x402 requirement in the handler's `config.requirement`
//! carries the exact amount in base units, and that is what is paid.
//!
//! Every checkout response carries `ap2.merchant_authorization`: a detached
//! JWS (RFC 7515 Appendix F) by the business key published in the profile's
//! `keys`, over the JCS (RFC 8785) canonical checkout without `ap2`. The
//! compact JWS formed by attaching that canonical checkout is the AP2
//! `checkout_jwt` a Payment Mandate's `transaction_id` hashes.
//!
//! `complete` takes `ap2.checkout_mandate`, an SD-JWT (`vct`
//! `mandate.checkout.1`) whose `checkout` claim is the checkout response the
//! user approved, and one `payment.instruments[]` entry under the `tenzro`
//! handler whose `credential.token` is the base64url JSON
//! `{"payment": <x402 PaymentPayload>, "payment_mandate": <SD-JWT>,
//! "open_payment_mandate": <SD-JWT, human-not-present flows>}`. The business
//! checks that the embedded checkout carries its own valid authorization and
//! matches the session, and that the checkout mandate is signed by the key
//! that signed the payment mandate (or the agent key an open mandate binds);
//! the mandates then travel in the payload's `extensions.ap2`, where the
//! facilitator holds them to the payer's DID, Terms, payee and amount before
//! funds move.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use p256::ecdsa::{Signature, VerifyingKey};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tower::ServiceExt;

use crate::acp::{ACP_API_VERSION, AcpState, TENZRO_HANDLER_ID, acp_router};
use crate::ap2::{AP2_EXTENSION_KEY, Ap2Presentation, VCT_CHECKOUT, VCT_PAYMENT_OPEN};

/// UCP version this business speaks.
pub const UCP_VERSION: &str = "2026-08-25";
/// Base of the versioned UCP documents.
pub const UCP_BASE: &str = "https://ucp.dev/2026-08-25";
/// The shopping service.
pub const SHOPPING_SERVICE: &str = "dev.ucp.shopping";
/// The checkout capability.
pub const CHECKOUT_CAPABILITY: &str = "dev.ucp.shopping.checkout";
/// The AP2 mandates extension of the checkout capability.
pub const AP2_MANDATE_CAPABILITY: &str = "dev.ucp.common.payment.ap2_mandate";
/// The Tenzro payment handler's name.
pub const TENZRO_HANDLER_NAME: &str = "dev.tenzro.x402";
/// Decimal places between a checkout amount and the asset's base unit.
pub const AMOUNT_SCALE: u32 = 9;

/// The business key checkout responses are authorized with.
pub trait MerchantKey: Send + Sync {
    /// The public key, published in the profile.
    fn public_key(&self) -> VerifyingKey;
    /// ES256 over `signing_input`.
    fn sign(&self, signing_input: &[u8]) -> std::result::Result<Signature, String>;
}

/// The RFC 7638 thumbprint of a P-256 key: its `kid` in the profile.
pub fn kid_of(key: &VerifyingKey) -> String {
    let jwk = crate::ap2::jwk_of(key);
    let canonical = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        jwk["x"].as_str().unwrap_or_default(),
        jwk["y"].as_str().unwrap_or_default()
    );
    B64.encode(Sha256::digest(canonical.as_bytes()))
}

/// The profile entry of a business key.
pub fn public_jwk(key: &VerifyingKey) -> Value {
    let mut jwk = crate::ap2::jwk_of(key);
    jwk["kid"] = json!(kid_of(key));
    jwk["alg"] = json!("ES256");
    jwk["use"] = json!("sig");
    jwk
}

/// JSON Canonicalization Scheme (RFC 8785) for the JSON this module signs:
/// object members sorted by their UTF-16 code units, no insignificant
/// whitespace, strings and integers as serde_json writes them.
pub fn jcs(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            let body: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", Value::String(k.clone()), jcs(&m[k])))
                .collect();
            format!("{{{}}}", body.join(","))
        }
        Value::Array(a) => format!("[{}]", a.iter().map(jcs).collect::<Vec<_>>().join(",")),
        other => other.to_string(),
    }
}

fn without_ap2(checkout: &Value) -> Value {
    let mut c = checkout.clone();
    if let Some(m) = c.as_object_mut() {
        m.remove("ap2");
    }
    c
}

fn jws_header(key: &VerifyingKey) -> String {
    let mut h = Map::new();
    h.insert("alg".into(), json!("ES256"));
    h.insert("kid".into(), json!(kid_of(key)));
    h.insert("jwk".into(), crate::ap2::jwk_of(key));
    B64.encode(serde_json::to_vec(&Value::Object(h)).unwrap_or_default())
}

/// The detached JWS authorizing `checkout` (its `ap2` member excluded).
pub fn merchant_authorization(
    key: &dyn MerchantKey,
    checkout: &Value,
) -> std::result::Result<String, String> {
    let h = jws_header(&key.public_key());
    let p = B64.encode(jcs(&without_ap2(checkout)).as_bytes());
    let sig = key.sign(format!("{h}.{p}").as_bytes())?;
    Ok(format!("{h}..{}", B64.encode(sig.to_bytes())))
}

/// The AP2 `checkout_jwt` of an authorized checkout: its
/// `ap2.merchant_authorization` with the canonical checkout attached.
pub fn checkout_jwt(checkout: &Value) -> Option<String> {
    let auth = checkout.pointer("/ap2/merchant_authorization")?.as_str()?;
    let (h, sig) = auth.split_once("..")?;
    let p = B64.encode(jcs(&without_ap2(checkout)).as_bytes());
    Some(format!("{h}.{p}.{sig}"))
}

/// Whether `checkout` carries an authorization by `key` over its content.
pub fn verify_merchant_authorization(key: &VerifyingKey, checkout: &Value) -> bool {
    use p256::ecdsa::signature::Verifier;
    let Some(jwt) = checkout_jwt(checkout) else {
        return false;
    };
    let mut parts = jwt.split('.');
    let (Some(h), Some(p), Some(s)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let header: Value = match B64
        .decode(h)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
    {
        Some(v) => v,
        None => return false,
    };
    if header["alg"] != "ES256" || header["kid"] != kid_of(key).as_str() {
        return false;
    }
    let Some(sig) = B64
        .decode(s)
        .ok()
        .and_then(|b| Signature::from_slice(&b).ok())
    else {
        return false;
    };
    key.verify(format!("{h}.{p}").as_bytes(), &sig).is_ok()
}

#[derive(Clone)]
struct UcpState {
    acp: Router,
    merchant: Arc<dyn MerchantKey>,
    endpoint: String,
    /// Idempotency key to the request it was first used with.
    keys: Arc<dashmap::DashMap<String, String>>,
}

/// The UCP router over `sessions`, authorizing checkouts with `merchant`.
/// `endpoint` is the absolute URL the checkout routes are served under, as
/// the profile states it.
pub fn ucp_router(
    sessions: AcpState,
    merchant: Arc<dyn MerchantKey>,
    endpoint: impl Into<String>,
) -> Router {
    let state = UcpState {
        acp: acp_router(sessions),
        merchant,
        endpoint: endpoint.into(),
        keys: Arc::new(dashmap::DashMap::new()),
    };
    Router::new()
        .route("/.well-known/ucp", get(profile))
        .route("/checkout-sessions", post(create))
        .route("/checkout-sessions/:id", get(read).put(update))
        .route("/checkout-sessions/:id/complete", post(complete))
        .route("/checkout-sessions/:id/cancel", post(cancel))
        .with_state(state)
}

fn handler_config() -> Value {
    json!({
        "amount_scale": AMOUNT_SCALE,
        "credential_token": "base64url JSON {payment: x402 PaymentPayload, payment_mandate, open_payment_mandate?}",
    })
}

async fn profile(State(state): State<UcpState>) -> Response {
    Json(json!({
        "ucp": {
            "version": UCP_VERSION,
            "services": {
                SHOPPING_SERVICE: [{
                    "version": UCP_VERSION,
                    "spec": format!("{UCP_BASE}/specification/overview/"),
                    "transport": "rest",
                    "endpoint": state.endpoint,
                    "schema": format!("{UCP_BASE}/services/shopping/rest.openapi.json"),
                }]
            },
            "capabilities": {
                CHECKOUT_CAPABILITY: [{
                    "version": UCP_VERSION,
                    "spec": format!("{UCP_BASE}/specification/shopping/checkout"),
                    "schema": format!("{UCP_BASE}/schemas/shopping/checkout.json"),
                }],
                AP2_MANDATE_CAPABILITY: [{
                    "version": UCP_VERSION,
                    "spec": format!("{UCP_BASE}/specification/payment/extensions/ap2-mandates"),
                    "schema": format!("{UCP_BASE}/schemas/common/payment_ap2_mandate.json"),
                    "extends": CHECKOUT_CAPABILITY,
                    "config": { "vp_formats_supported": { "dc+sd-jwt": {} } },
                }],
            },
            "payment_handlers": {
                TENZRO_HANDLER_NAME: [{
                    "id": TENZRO_HANDLER_ID,
                    "version": UCP_VERSION,
                    "spec": "https://github.com/x402-foundation/x402",
                    "config": handler_config(),
                }]
            },
        },
        "keys": [public_jwk(&state.merchant.public_key())],
    }))
    .into_response()
}

/// A protocol error: `status` with `code` and `content`.
fn protocol_error(status: StatusCode, code: &str, content: impl Into<String>) -> Response {
    (
        status,
        Json(json!({ "code": code, "content": content.into() })),
    )
        .into_response()
}

/// A business outcome without a checkout: 200 with the UCP error envelope.
fn outcome_error(code: &str, content: impl Into<String>) -> Response {
    (
        StatusCode::OK,
        Json(json!({
            "ucp": { "version": UCP_VERSION, "status": "error" },
            "messages": [message(code, content)],
        })),
    )
        .into_response()
}

fn message(code: &str, content: impl Into<String>) -> Value {
    json!({ "type": "error", "code": code, "content": content.into(), "severity": "recoverable" })
}

fn nano(base_units: &str) -> u64 {
    let wei: u128 = base_units.parse().unwrap_or(0);
    let scale = 10u128.pow(AMOUNT_SCALE);
    u64::try_from(wei.div_ceil(scale)).unwrap_or(u64::MAX)
}

fn ucp_totals(acp: &Value) -> Value {
    let amount = |ty: &str| {
        acp.as_array()
            .and_then(|a| a.iter().find(|t| t["type"] == ty))
            .and_then(|t| t["amount"].as_str())
            .map(nano)
            .unwrap_or(0)
    };
    json!([
        { "type": "subtotal", "display_text": "Subtotal", "amount": amount("subtotal").max(amount("items_base_amount")) },
        { "type": "total", "display_text": "Total", "amount": amount("total") },
    ])
}

/// An ACP session as a UCP checkout, authorized by the business key.
fn checkout(
    state: &UcpState,
    acp: &Value,
    messages: Vec<Value>,
) -> std::result::Result<Value, String> {
    let status = match acp["status"].as_str() {
        Some("ready_for_payment") => "ready_for_complete",
        Some("completed") => "completed",
        Some("canceled") | Some("expired") => "canceled",
        _ => "incomplete",
    };
    let line_items: Vec<Value> = acp["line_items"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|li| {
                    let id = li.pointer("/item/id").cloned().unwrap_or(Value::Null);
                    let unit = li["unit_amount"].as_str().map(nano).unwrap_or(0);
                    json!({
                        "id": li["id"],
                        "item": { "id": id, "title": id, "price": unit },
                        "quantity": li["quantity"],
                        "totals": ucp_totals(&li["totals"]),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let requirement = acp
        .pointer("/capabilities/payment/handlers/0/config/requirement")
        .cloned()
        .unwrap_or(Value::Null);
    let mut config = handler_config();
    config["requirement"] = requirement;
    let mut out = json!({
        "ucp": {
            "version": UCP_VERSION,
            "status": "success",
            "capabilities": {
                CHECKOUT_CAPABILITY: [{ "version": UCP_VERSION }],
                AP2_MANDATE_CAPABILITY: [{ "version": UCP_VERSION }],
            },
            "payment_handlers": {
                TENZRO_HANDLER_NAME: [{ "id": TENZRO_HANDLER_ID, "version": UCP_VERSION, "config": config }]
            },
        },
        "id": acp["id"],
        "line_items": line_items,
        "status": status,
        "currency": acp["currency"],
        "totals": ucp_totals(&acp["totals"]),
        "links": [],
        "expires_at": acp["expires_at"],
    });
    if !messages.is_empty() {
        out["messages"] = Value::Array(messages);
    }
    if let Some(order) = acp.get("order") {
        out["order"] = json!({
            "id": order["id"],
            "permalink_url": order["permalink_url"],
        });
    }
    let auth = merchant_authorization(state.merchant.as_ref(), &out)?;
    out["ap2"] = json!({ "merchant_authorization": auth });
    Ok(out)
}

/// Refuse with 409 an `Idempotency-Key` used before with another request.
fn claim_key(
    state: &UcpState,
    headers: &HeaderMap,
    route: &str,
    body: &Value,
) -> std::result::Result<(), Response> {
    let Some(key) = headers.get("idempotency-key").and_then(|v| v.to_str().ok()) else {
        return Ok(());
    };
    let fingerprint = format!("{route}\n{}", jcs(body));
    let prior = state
        .keys
        .entry(key.to_string())
        .or_insert_with(|| fingerprint.clone())
        .clone();
    if prior != fingerprint {
        return Err(protocol_error(
            StatusCode::CONFLICT,
            "idempotency_conflict",
            "this Idempotency-Key was used with another request",
        ));
    }
    Ok(())
}

/// The headers every UCP request carries.
fn check_headers(headers: &HeaderMap, mutating: bool) -> std::result::Result<(), Response> {
    let has = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| !v.is_empty())
    };
    if !has("ucp-agent") {
        return Err(protocol_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "UCP-Agent is required: profile=\"<platform profile URI>\"",
        ));
    }
    if !has("request-id") {
        return Err(protocol_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Request-Id is required",
        ));
    }
    if mutating && !has("idempotency-key") {
        return Err(protocol_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Idempotency-Key is required",
        ));
    }
    Ok(())
}

/// Run `method path` on the session machine and return its status and
/// answer.
async fn acp_call(
    state: &UcpState,
    method: Method,
    path: String,
    headers: &HeaderMap,
    body: Option<Value>,
) -> std::result::Result<(StatusCode, Value, bool), Response> {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("api-version", ACP_API_VERSION);
    if let Some(key) = headers.get("idempotency-key") {
        req = req.header("idempotency-key", key);
    }
    let req = match body {
        Some(b) => req
            .header("content-type", "application/json")
            .body(Body::from(b.to_string())),
        None => req.body(Body::empty()),
    }
    .map_err(|_| {
        protocol_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "malformed request",
        )
    })?;
    let Ok(resp) = state.acp.clone().oneshot(req).await;
    let status = resp.status();
    let replayed = resp.headers().contains_key("idempotent-replayed");
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .map_err(|_| {
            protocol_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "unreadable answer",
            )
        })?;
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Ok((status, v, replayed))
}

/// Answer an ACP result as UCP.
fn answer(
    state: &UcpState,
    status: StatusCode,
    acp: Value,
    replayed: bool,
    ok: StatusCode,
) -> Response {
    if acp.get("id").is_some() && status.is_success() {
        return match checkout(state, &acp, Vec::new()) {
            Ok(c) => {
                let mut r = (ok, Json(c)).into_response();
                if replayed {
                    r.headers_mut().insert(
                        "idempotent-replayed",
                        axum::http::HeaderValue::from_static("true"),
                    );
                }
                r
            }
            Err(e) => protocol_error(StatusCode::SERVICE_UNAVAILABLE, "signing_unavailable", e),
        };
    }
    let code = acp["code"]
        .as_str()
        .unwrap_or("invalid_request")
        .to_string();
    let content = acp["message"].as_str().unwrap_or("refused").to_string();
    match (status, code.as_str()) {
        (StatusCode::UNPROCESSABLE_ENTITY, "idempotency_conflict") => {
            protocol_error(StatusCode::CONFLICT, "idempotency_conflict", content)
        }
        (StatusCode::NOT_FOUND, _) => protocol_error(StatusCode::NOT_FOUND, "not_found", content),
        (StatusCode::METHOD_NOT_ALLOWED, _) => outcome_error("invalid_state", content),
        (_, "out_of_stock") => outcome_error("item_unavailable", content),
        _ => outcome_error(&code, content),
    }
}

fn line_items(body: &Value) -> Value {
    match body["line_items"].as_array() {
        Some(items) => Value::Array(
            items
                .iter()
                .map(|li| json!({ "item": { "id": li.pointer("/item/id").cloned().unwrap_or(Value::Null) },
                                  "quantity": li.get("quantity").cloned().unwrap_or(json!(1)) }))
                .collect(),
        ),
        None => Value::Null,
    }
}

async fn create(
    State(state): State<UcpState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) =
        check_headers(&headers, true).and_then(|()| claim_key(&state, &headers, "create", &body))
    {
        return r;
    }
    let acp = json!({ "currency": "TNZO", "line_items": line_items(&body) });
    match acp_call(
        &state,
        Method::POST,
        "/checkout_sessions".into(),
        &headers,
        Some(acp),
    )
    .await
    {
        Ok((status, v, replayed)) => answer(&state, status, v, replayed, StatusCode::CREATED),
        Err(r) => r,
    }
}

async fn read(
    State(state): State<UcpState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = check_headers(&headers, false) {
        return r;
    }
    match acp_call(
        &state,
        Method::GET,
        format!("/checkout_sessions/{id}"),
        &headers,
        None,
    )
    .await
    {
        Ok((status, v, replayed)) => answer(&state, status, v, replayed, StatusCode::OK),
        Err(r) => r,
    }
}

async fn update(
    State(state): State<UcpState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = check_headers(&headers, true)
        .and_then(|()| claim_key(&state, &headers, &format!("update/{id}"), &body))
    {
        return r;
    }
    let acp = json!({ "line_items": line_items(&body) });
    match acp_call(
        &state,
        Method::POST,
        format!("/checkout_sessions/{id}"),
        &headers,
        Some(acp),
    )
    .await
    {
        Ok((status, v, replayed)) => answer(&state, status, v, replayed, StatusCode::OK),
        Err(r) => r,
    }
}

async fn cancel(
    State(state): State<UcpState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = check_headers(&headers, true)
        .and_then(|()| claim_key(&state, &headers, &format!("cancel/{id}"), &body))
    {
        return r;
    }
    match acp_call(
        &state,
        Method::POST,
        format!("/checkout_sessions/{id}/cancel"),
        &headers,
        Some(json!({})),
    )
    .await
    {
        Ok((status, v, replayed)) => answer(&state, status, v, replayed, StatusCode::OK),
        Err(r) => r,
    }
}

/// The checkout as it stands, with `code` refusing the completion.
async fn refused(
    state: &UcpState,
    id: &str,
    headers: &HeaderMap,
    code: &str,
    content: impl Into<String>,
) -> Response {
    match acp_call(
        state,
        Method::GET,
        format!("/checkout_sessions/{id}"),
        headers,
        None,
    )
    .await
    {
        Ok((s, v, _)) if s.is_success() => {
            match checkout(state, &v, vec![message(code, content)]) {
                Ok(c) => (StatusCode::OK, Json(c)).into_response(),
                Err(e) => protocol_error(StatusCode::SERVICE_UNAVAILABLE, "signing_unavailable", e),
            }
        }
        Ok((s, v, r)) => answer(state, s, v, r, StatusCode::OK),
        Err(r) => r,
    }
}

/// Fields of the session the user's approval must match.
fn terms(c: &Value) -> Value {
    json!({ "id": c["id"], "currency": c["currency"], "totals": c["totals"], "line_items": c["line_items"] })
}

async fn complete(
    State(state): State<UcpState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = check_headers(&headers, true)
        .and_then(|()| claim_key(&state, &headers, &format!("complete/{id}"), &body))
    {
        return r;
    }
    // The session as it stands now, as this business presents it.
    let current = match acp_call(
        &state,
        Method::GET,
        format!("/checkout_sessions/{id}"),
        &headers,
        None,
    )
    .await
    {
        Ok((s, v, _)) if s.is_success() => v,
        Ok((s, v, r)) => return answer(&state, s, v, r, StatusCode::OK),
        Err(r) => return r,
    };
    let current = match checkout(&state, &current, Vec::new()) {
        Ok(c) => c,
        Err(e) => return protocol_error(StatusCode::SERVICE_UNAVAILABLE, "signing_unavailable", e),
    };

    let Some(checkout_mandate) = body
        .pointer("/ap2/checkout_mandate")
        .and_then(Value::as_str)
    else {
        return refused(
            &state,
            &id,
            &headers,
            "mandate_required",
            "ap2.checkout_mandate is required",
        )
        .await;
    };
    let instruments: Vec<&Value> = body
        .pointer("/payment/instruments")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter(|i| i["handler_id"] == TENZRO_HANDLER_ID)
                .collect()
        })
        .unwrap_or_default();
    let [instrument] = instruments.as_slice() else {
        return refused(
            &state,
            &id,
            &headers,
            "payment_declined",
            "complete with one instrument under the tenzro handler",
        )
        .await;
    };
    let token = match instrument
        .pointer("/credential/token")
        .and_then(Value::as_str)
        .and_then(|t| B64.decode(t).ok())
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
    {
        Some(t) => t,
        None => {
            return refused(
                &state,
                &id,
                &headers,
                "payment_declined",
                "credential.token is base64url JSON {payment, payment_mandate}",
            )
            .await;
        }
    };
    let Some(payment_mandate) = token["payment_mandate"].as_str() else {
        return refused(
            &state,
            &id,
            &headers,
            "mandate_required",
            "the payment mandate travels in credential.token",
        )
        .await;
    };
    let open_mandate = token["open_payment_mandate"].as_str();

    // The checkout mandate: the user's approval of this business's checkout.
    // The UCP schema writes it without the closing `~` an SD-JWT without key
    // binding ends with; both forms are read.
    let checkout_mandate = if !checkout_mandate.ends_with('~')
        && !checkout_mandate
            .rsplit('~')
            .next()
            .unwrap_or_default()
            .contains('.')
    {
        format!("{checkout_mandate}~")
    } else {
        checkout_mandate.to_string()
    };
    let approved = match crate::ap2::verify_sd_jwt(&checkout_mandate) {
        Ok(v) => v,
        Err(e) => {
            return refused(
                &state,
                &id,
                &headers,
                "mandate_invalid_signature",
                e.to_string(),
            )
            .await;
        }
    };
    if approved.claims["vct"] != VCT_CHECKOUT {
        return refused(
            &state,
            &id,
            &headers,
            "mandate_invalid_signature",
            format!("the checkout mandate's vct is not {VCT_CHECKOUT}"),
        )
        .await;
    }
    if approved.claims["exp"]
        .as_i64()
        .is_some_and(|exp| chrono::Utc::now().timestamp() >= exp)
    {
        return refused(
            &state,
            &id,
            &headers,
            "mandate_expired",
            "the checkout mandate expired",
        )
        .await;
    }
    let embedded = &approved.claims["checkout"];
    if embedded.pointer("/ap2/merchant_authorization").is_none() {
        return refused(
            &state,
            &id,
            &headers,
            "merchant_authorization_missing",
            "the approved checkout carries no merchant authorization",
        )
        .await;
    }
    if !verify_merchant_authorization(&state.merchant.public_key(), embedded) {
        return refused(
            &state,
            &id,
            &headers,
            "merchant_authorization_invalid",
            "the approved checkout is not authorized by this business",
        )
        .await;
    }
    if terms(embedded) != terms(&current) {
        return refused(
            &state,
            &id,
            &headers,
            "mandate_scope_mismatch",
            "the approved checkout is not this checkout as it stands",
        )
        .await;
    }
    // The key that approved the checkout authorized the payment: it signed
    // the payment mandate, or is the agent key the open mandate binds.
    let payment_signer = match crate::ap2::verify_sd_jwt(payment_mandate) {
        Ok(v) => v.issuer_key,
        Err(e) => {
            return refused(
                &state,
                &id,
                &headers,
                "mandate_invalid_signature",
                e.to_string(),
            )
            .await;
        }
    };
    let agent_key = open_mandate
        .and_then(|m| crate::ap2::verify_sd_jwt(m).ok())
        .filter(|o| o.claims["vct"] == VCT_PAYMENT_OPEN)
        .and_then(|o| {
            o.claims
                .pointer("/cnf/jwk")
                .and_then(|j| crate::ap2::key_from_jwk(j).ok())
        });
    if approved.issuer_key != payment_signer && Some(approved.issuer_key) != agent_key {
        return refused(
            &state,
            &id,
            &headers,
            "mandate_invalid_signature",
            "the checkout and payment mandates are signed by unrelated keys",
        )
        .await;
    }

    let Some(checkout_jwt) = checkout_jwt(embedded) else {
        return refused(
            &state,
            &id,
            &headers,
            "merchant_authorization_invalid",
            "the approved checkout's authorization is malformed",
        )
        .await;
    };
    let mut payload = token["payment"].clone();
    if !payload.is_object() {
        return refused(
            &state,
            &id,
            &headers,
            "payment_declined",
            "credential.token names no x402 payment",
        )
        .await;
    }
    if payload.get("extensions").is_none_or(|e| !e.is_object()) {
        payload["extensions"] = json!({});
    }
    payload["extensions"][AP2_EXTENSION_KEY] = serde_json::to_value(Ap2Presentation {
        checkout_jwt,
        payment_mandate: payment_mandate.to_string(),
        open_payment_mandate: open_mandate.map(str::to_string),
    })
    .unwrap_or(Value::Null);
    let acp = json!({ "payment_data": { "handler_id": TENZRO_HANDLER_ID,
        "instrument": { "type": "x402", "credential": payload } } });
    match acp_call(
        &state,
        Method::POST,
        format!("/checkout_sessions/{id}/complete"),
        &headers,
        Some(acp),
    )
    .await
    {
        Ok((StatusCode::PAYMENT_REQUIRED, v, _)) => {
            let reason = v["messages"][0]["content"]
                .as_str()
                .unwrap_or("payment refused")
                .to_string();
            match checkout(&state, &v, vec![message("payment_declined", reason)]) {
                Ok(c) => (StatusCode::OK, Json(c)).into_response(),
                Err(e) => protocol_error(StatusCode::SERVICE_UNAVAILABLE, "signing_unavailable", e),
            }
        }
        Ok((status, v, replayed)) => answer(&state, status, v, replayed, StatusCode::OK),
        Err(r) => r,
    }
}
