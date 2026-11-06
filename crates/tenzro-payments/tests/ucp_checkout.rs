//! UCP checkout against the published specification: every request and
//! response body of a checkout completed under the AP2 mandates extension is
//! validated with the UCP JSON schemas of version 2026-08-25, vendored
//! unmodified under `tests/fixtures/ucp-2026-08-25` from
//! <https://github.com/Universal-Commerce-Protocol/ucp> at tag `v2026-08-25`
//! (Apache-2.0, see the LICENSE there).

use std::sync::Arc;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use parking_lot::Mutex;
use serde_json::{Map, Value, json};
use tenzro_payments::acp::{AcpState, Seller};
use tenzro_payments::ap2::{
    Ap2Presentation, VCT_CHECKOUT, VCT_PAYMENT, b64_sha256, jwk_of, sign_jws,
};
use tenzro_payments::ucp::{self, MerchantKey};
use tenzro_payments::x402::{X402PaymentPayload, X402PaymentRequirement, X402SettlementResponse};
use tower::ServiceExt;

const PAYEE: &str = "0909090909090909090909090909090909090909";

struct Schemas {
    schemas: boon::Schemas,
    compiler: boon::Compiler,
}

impl Schemas {
    fn load() -> Self {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/ucp-2026-08-25/schemas");
        let mut compiler = boon::Compiler::new();
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("schema dir") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "json") {
                    let doc: Value =
                        serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("json");
                    let rel = path
                        .strip_prefix(&root)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/");
                    compiler
                        .add_resource(&format!("https://ucp.dev/schemas/{rel}"), doc)
                        .expect("schema resource");
                }
            }
        }
        Self {
            schemas: boon::Schemas::new(),
            compiler,
        }
    }

    /// Validate `instance` against the schema at `loc` under
    /// `https://ucp.dev/schemas/`.
    fn check(&mut self, loc: &str, instance: &Value, what: &str) {
        let url = format!("https://ucp.dev/schemas/{loc}");
        let idx = self
            .compiler
            .compile(&url, &mut self.schemas)
            .unwrap_or_else(|e| panic!("{loc}: {e}"));
        if let Err(e) = self.schemas.validate(instance, idx) {
            panic!("{what} does not validate against {loc}: {e:#}\n{instance:#}");
        }
    }
}

struct TestMerchant(SigningKey);

impl MerchantKey for TestMerchant {
    fn public_key(&self) -> VerifyingKey {
        *self.0.verifying_key()
    }
    fn sign(&self, input: &[u8]) -> Result<Signature, String> {
        Ok(self.0.sign(input))
    }
}

/// Sells `model-a` at 2 TNZO per unit; settles a payload for the
/// requirement that carries AP2 mandates, recording them.
struct Shop(Mutex<Vec<Ap2Presentation>>);

#[async_trait]
impl Seller for Shop {
    fn price(&self, item_id: &str, quantity: u64) -> Result<(u128, String), String> {
        match item_id {
            "model-a" => Ok((
                2_000_000_000_000_000_000 * u128::from(quantity),
                "TNZO".into(),
            )),
            _ => Err("not served here".into()),
        }
    }
    fn requirement(&self, session_id: &str, total: u128, asset: &str) -> X402PaymentRequirement {
        let mut r = X402PaymentRequirement::new(
            "tenzro-hybrid",
            "tenzro:1337",
            total.to_string(),
            PAYEE,
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
        match tenzro_payments::ap2::presentation_in(payload.extensions.as_ref()) {
            Ok(Some(m)) if payload.accepted == *requirement => {
                self.0.lock().push(m);
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
            }
            _ => X402SettlementResponse::failed(requirement.network.clone(), "no mandates"),
        }
    }
}

/// An SD-JWT by `k` with every claim but `vct` and `cnf` selectively
/// disclosed, and no key binding.
fn sd_jwt(k: &SigningKey, claims: Value) -> String {
    let mut digests = Vec::new();
    let mut discs = Vec::new();
    let mut body = Map::new();
    for (name, v) in claims.as_object().unwrap() {
        if name == "vct" || name == "cnf" {
            body.insert(name.clone(), v.clone());
            continue;
        }
        let d = B64.encode(serde_json::to_vec(&json!(["salt", name, v])).unwrap());
        digests.push(Value::String(b64_sha256(d.as_bytes())));
        discs.push(d);
    }
    body.insert("_sd".into(), Value::Array(digests));
    body.insert("_sd_alg".into(), "sha-256".into());
    let mut h = Map::new();
    h.insert("alg".into(), "ES256".into());
    h.insert("jwk".into(), jwk_of(k.verifying_key()));
    let mut out = sign_jws(&h, &Value::Object(body), |m| k.sign(m));
    for d in discs {
        out.push('~');
        out.push_str(&d);
    }
    out.push('~');
    out
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// A checkout mandate as the UCP schema writes it: the SD-JWT and its
/// disclosures, without a closing `~`.
fn checkout_mandate(signer: &SigningKey, checkout: &Value) -> String {
    sd_jwt(
        signer,
        json!({ "vct": VCT_CHECKOUT, "checkout": checkout, "exp": now() + 600 }),
    )
    .trim_end_matches('~')
    .to_string()
}

fn payment_mandate(signer: &SigningKey, checkout: &Value) -> String {
    let req = requirement(checkout);
    sd_jwt(
        signer,
        json!({
            "vct": VCT_PAYMENT,
            "transaction_id": b64_sha256(ucp::checkout_jwt(checkout).unwrap().as_bytes()),
            "payee": { "id": req["payTo"].as_str().or(req["pay_to"].as_str()), "name": "seller" },
            "payment_amount": { "amount": req["amount"], "currency": "TNZO" },
            "payment_instrument": { "id": "tenzro-wallet", "type": "tenzro" },
            "exp": now() + 600,
        }),
    )
}

fn requirement(checkout: &Value) -> Value {
    checkout["ucp"]["payment_handlers"][ucp::TENZRO_HANDLER_NAME][0]["config"]["requirement"]
        .clone()
}

fn complete_body(
    checkout: &Value,
    checkout_mandate: Option<String>,
    payment_mandate: &str,
) -> Value {
    let token = json!({
        "payment": { "x402Version": 2, "accepted": requirement(checkout), "payload": {} },
        "payment_mandate": payment_mandate,
    });
    let mut body = json!({
        "payment": { "instruments": [{
            "id": "instr_1", "handler_id": "tenzro", "type": "tenzro_x402", "selected": true,
            "credential": { "type": "x402", "token": B64.encode(token.to_string()) }
        }] }
    });
    if let Some(m) = checkout_mandate {
        body["ap2"] = json!({ "checkout_mandate": m });
    }
    body
}

async fn call(
    r: &Router,
    method: &str,
    path: &str,
    key: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header(
            "ucp-agent",
            "profile=\"https://platform.example/.well-known/ucp\"",
        )
        .header("request-id", "6c3e8f0e-6c87-4c5e-9d1c-2a9f6f2f8a01");
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
    let resp = r.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

const CHECKOUT_WITH_AP2: &str = "common/payment_ap2_mandate.json#/$defs/dev.ucp.shopping.checkout";

/// A platform checks out over UCP 2026-08-25 under the AP2 mandates
/// extension and pays under the Tenzro handler. Every body validates against
/// the published schemas; the business authorizes each checkout with the key
/// its profile publishes; completion is refused without a checkout mandate,
/// for a checkout that is no longer the current one, and when the checkout
/// and payment mandates are signed by unrelated keys; with valid mandates the
/// seller settles a payment carrying exactly them, once.
#[tokio::test]
async fn a_checkout_validates_against_the_published_schemas_and_completes_with_ap2_mandates() {
    let mut schemas = Schemas::load();
    let merchant = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let user = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let stranger = SigningKey::from_slice(&[11u8; 32]).unwrap();
    let shop = Arc::new(Shop(Mutex::new(Vec::new())));
    let r = ucp::ucp_router(
        AcpState::new(shop.clone()),
        Arc::new(TestMerchant(merchant.clone())),
        "https://node.example/ucp",
    );

    let (st, profile) = call(&r, "GET", "/.well-known/ucp", None, None).await;
    assert_eq!(st, StatusCode::OK);
    schemas.check(
        "profile.json#/$defs/business_schema",
        &profile,
        "the profile",
    );
    assert_eq!(
        profile["keys"][0]["kid"],
        ucp::kid_of(merchant.verifying_key())
    );

    let create = json!({ "line_items": [{ "item": { "id": "model-a" }, "quantity": 3 }] });
    schemas.check(
        "shopping/types/item.json#/properties/id",
        &create["line_items"][0]["item"]["id"],
        "the create item id",
    );
    let (st, first) = call(
        &r,
        "POST",
        "/checkout-sessions",
        Some("4c1d1b7e-0001-4000-8000-000000000001"),
        Some(create),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{first}");
    schemas.check(CHECKOUT_WITH_AP2, &first, "the created checkout");
    assert_eq!(first["status"], "ready_for_complete");
    assert_eq!(first["totals"][1]["amount"], 6_000_000_000u64, "nano-TNZO");
    assert!(ucp::verify_merchant_authorization(
        merchant.verifying_key(),
        &first
    ));
    let id = first["id"].as_str().unwrap().to_string();

    let (st, c) = call(
        &r,
        "PUT",
        &format!("/checkout-sessions/{id}"),
        Some("4c1d1b7e-0001-4000-8000-000000000002"),
        Some(json!({ "line_items": [{ "item": { "id": "model-a" }, "quantity": 5 }] })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{c}");
    schemas.check(CHECKOUT_WITH_AP2, &c, "the updated checkout");
    assert_eq!(c["totals"][1]["amount"], 10_000_000_000u64);
    assert_eq!(requirement(&c)["amount"], "10000000000000000000");

    let path = format!("/checkout-sessions/{id}/complete");
    let pm = payment_mandate(&user, &c);
    let refusal = |body: &Value, code: &str| {
        assert_eq!(body["status"], "ready_for_complete", "{body}");
        assert_eq!(body["messages"][0]["code"], code, "{body}");
    };

    // No checkout mandate.
    let body = complete_body(&c, None, &pm);
    schemas.check(
        "common/types/payment.json",
        &body["payment"],
        "the complete payment",
    );
    let (st, out) = call(
        &r,
        "POST",
        &path,
        Some("4c1d1b7e-0001-4000-8000-000000000003"),
        Some(body),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    schemas.check(CHECKOUT_WITH_AP2, &out, "a refused completion");
    refusal(&out, "mandate_required");

    // A mandate over the checkout before it was updated.
    let body = complete_body(
        &first,
        Some(checkout_mandate(&user, &first)),
        &payment_mandate(&user, &first),
    );
    let (_, out) = call(
        &r,
        "POST",
        &path,
        Some("4c1d1b7e-0001-4000-8000-000000000004"),
        Some(body),
    )
    .await;
    refusal(&out, "mandate_scope_mismatch");

    // A checkout whose terms were changed after the business signed them.
    let mut forged = c.clone();
    forged["totals"][1]["amount"] = json!(1);
    let (_, out) = call(
        &r,
        "POST",
        &path,
        Some("4c1d1b7e-0001-4000-8000-000000000005"),
        Some(complete_body(
            &c,
            Some(checkout_mandate(&user, &forged)),
            &pm,
        )),
    )
    .await;
    refusal(&out, "merchant_authorization_invalid");

    // Mandates signed by unrelated keys.
    let (_, out) = call(
        &r,
        "POST",
        &path,
        Some("4c1d1b7e-0001-4000-8000-000000000006"),
        Some(complete_body(
            &c,
            Some(checkout_mandate(&stranger, &c)),
            &pm,
        )),
    )
    .await;
    refusal(&out, "mandate_invalid_signature");
    assert!(shop.0.lock().is_empty(), "nothing was settled");

    // The approved checkout, paid under the Tenzro handler.
    let cm = checkout_mandate(&user, &c);
    let body = complete_body(&c, Some(cm.clone()), &pm);
    schemas.check(
        "common/payment_ap2_mandate.json#/$defs/ap2_with_checkout_mandate",
        &body["ap2"],
        "the complete ap2",
    );
    schemas.check(
        "common/payment_ap2_mandate.json#/$defs/checkout_mandate",
        &body["ap2"]["checkout_mandate"],
        "the checkout mandate",
    );
    let (st, done) = call(
        &r,
        "POST",
        &path,
        Some("4c1d1b7e-0001-4000-8000-000000000007"),
        Some(body.clone()),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{done}");
    schemas.check(CHECKOUT_WITH_AP2, &done, "the completed checkout");
    assert_eq!(done["status"], "completed");
    assert!(done["order"]["id"].is_string());
    let paid = shop.0.lock().clone();
    assert_eq!(paid.len(), 1);
    assert_eq!(paid[0].payment_mandate, pm);
    assert_eq!(paid[0].checkout_jwt, ucp::checkout_jwt(&c).unwrap());

    // The same key with another body is a conflict; a new key does not pay again.
    let (st, conflict) = call(
        &r,
        "POST",
        &path,
        Some("4c1d1b7e-0001-4000-8000-000000000007"),
        Some(json!({ "ap2": { "checkout_mandate": cm } })),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "{conflict}");
    let (st, again) = call(
        &r,
        "POST",
        &path,
        Some("4c1d1b7e-0001-4000-8000-000000000008"),
        Some(body),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    schemas.check(
        "common/types/error_response.json",
        &again,
        "a second completion",
    );
    assert_eq!(again["messages"][0]["code"], "invalid_state", "{again}");
    assert_eq!(shop.0.lock().len(), 1, "paid once");

    let (st, got) = call(&r, "GET", &format!("/checkout-sessions/{id}"), None, None).await;
    assert_eq!(st, StatusCode::OK);
    schemas.check(CHECKOUT_WITH_AP2, &got, "the checkout read back");

    let (st, missing) = call(&r, "GET", "/checkout-sessions/nope", None, None).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{missing}");
}

/// A request without the platform's UCP-Agent is refused before anything
/// else.
#[tokio::test]
async fn a_request_without_ucp_agent_is_refused() {
    let r = ucp::ucp_router(
        AcpState::new(Arc::new(Shop(Mutex::new(Vec::new())))),
        Arc::new(TestMerchant(SigningKey::from_slice(&[7u8; 32]).unwrap())),
        "https://node.example/ucp",
    );
    let req = Request::builder()
        .method("POST")
        .uri("/checkout-sessions")
        .header("request-id", "6c3e8f0e-6c87-4c5e-9d1c-2a9f6f2f8a01")
        .header("idempotency-key", "4c1d1b7e-0001-4000-8000-000000000009")
        .header("content-type", "application/json")
        .body(Body::from(json!({ "line_items": [] }).to_string()))
        .unwrap();
    assert_eq!(
        r.oneshot(req).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
}
