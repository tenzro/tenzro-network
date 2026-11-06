//! The Tenzro inference provider a sandbox reaches through
//! `providers/tenzro.yaml`.
//!
//! An OpenAI-compatible endpoint. The sandbox's request carries the
//! short-lived credential the credential driver minted (OpenShell injects it
//! at egress; the sandbox holds only a placeholder). Each call is checked
//! before it runs: the credential's signature and expiry, the agent's and its
//! root's revocation state, and the Terms for `inference` on the requested
//! model with the call's ceiling (`max_tokens` at the per-unit price). The
//! call is routed through the Tenzro network ([`Route`]), settled per unit
//! from the agent's wallet once its usage is known, and answered with the
//! signed receipt of the model call in [`RECEIPT_HEADER`].

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value as Json, json};
use tenzro_crypto::composite::CompositePublicKey;
use tenzro_types::agent_audit::{ActionKind, ActionOutcome, SignedAuditEntry};
use tenzro_types::primitives::Address;

use crate::authority::{Authority, Proposed};
use crate::middleware::RECEIPT_HEADER;
use crate::records::{Decision, RecordLog};

/// Where a call is served: a Tenzro node's OpenAI-compatible API.
#[async_trait::async_trait]
pub trait Route: Send + Sync {
    /// Serve `request`; returns the response and the units it used.
    async fn complete(&self, request: &Json) -> Result<(Json, u64), String>;
}

/// Routes calls to a Tenzro node's `/v1/chat/completions`.
pub struct NodeRoute {
    base: String,
    client: reqwest::Client,
}

impl NodeRoute {
    /// A route to the node at `base` (`https://…`, no trailing slash).
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into(),
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl Route for NodeRoute {
    async fn complete(&self, request: &Json) -> Result<(Json, u64), String> {
        let r = self
            .client
            .post(format!("{}/v1/chat/completions", self.base))
            .json(request)
            .send()
            .await
            .map_err(|e| format!("upstream: {e}"))?;
        let status = r.status();
        let body: Json = r.json().await.map_err(|e| format!("upstream body: {e}"))?;
        if !status.is_success() {
            return Err(format!("upstream answered {status}: {body}"));
        }
        let units = body
            .pointer("/usage/total_tokens")
            .and_then(Json::as_u64)
            .ok_or("upstream reported no usage")?;
        Ok((body, units))
    }
}

/// Pricing and the account calls are paid to.
#[derive(Debug, Clone)]
pub struct Pricing {
    /// Price of one unit (token), smallest unit of TNZO.
    pub per_unit: u128,
    /// The ceiling a call without `max_tokens` is checked at.
    pub default_max_units: u64,
    /// The account calls settle to.
    pub payee: Address,
}

/// The provider endpoint.
pub struct TenzroProvider {
    authority: Arc<dyn Authority>,
    issuer: CompositePublicKey,
    records: Arc<RecordLog>,
    route: Arc<dyn Route>,
    pricing: Pricing,
}

/// The settlement reference a receipt header names.
pub fn receipt_reference(header: &str) -> String {
    B64.decode(header)
        .ok()
        .and_then(|b| serde_json::from_slice::<SignedAuditEntry>(&b).ok())
        .and_then(|s| s.entry().ok())
        .and_then(|e| e.linked_tx)
        .unwrap_or_else(|| {
            hex::encode(crate::digest(
                b"tenzro/openshell/receipt/v1",
                &[header.as_bytes()],
            ))
        })
}

fn refuse(status: StatusCode, why: &str) -> Response {
    (
        status,
        axum::Json(json!({"error": {"message": why, "type": "tenzro_refusal"}})),
    )
        .into_response()
}

impl TenzroProvider {
    /// A provider accepting credentials the serving node `issuer` minted.
    pub fn new(
        authority: Arc<dyn Authority>,
        issuer: CompositePublicKey,
        records: Arc<RecordLog>,
        route: Arc<dyn Route>,
        pricing: Pricing,
    ) -> Arc<Self> {
        Arc::new(Self {
            authority,
            issuer,
            records,
            route,
            pricing,
        })
    }

    /// The OpenAI-compatible routes.
    pub fn router(self: Arc<Self>) -> axum::Router {
        axum::Router::new()
            .route("/v1/chat/completions", post(chat))
            .route("/v1/models", get(models))
            .with_state(self)
    }

    fn record(
        &self,
        agent: &str,
        model: &str,
        outcome: ActionOutcome,
        detail: &[u8],
        tx: Option<String>,
    ) -> Option<SignedAuditEntry> {
        let kind = match &outcome {
            ActionOutcome::Refused(r) if r == crate::authority::REVOKED => ActionKind::GrantUse,
            _ => ActionKind::ModelCall,
        };
        self.records
            .record(Decision {
                session: agent,
                agent,
                kind,
                action: model,
                outcome,
                detail,
                linked_tx: tx,
            })
            .map_err(|e| tracing::error!("model call record not written: {e}"))
            .ok()
    }

    async fn serve(&self, headers: &HeaderMap, body: Json) -> Response {
        let now = crate::now_ms();
        let Some(bearer) = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
        else {
            return refuse(StatusCode::UNAUTHORIZED, "no Tenzro credential");
        };
        let claims = match crate::token::verify(&self.issuer, bearer.trim(), now) {
            Ok(c) if c.scope == "inference" => c,
            Ok(_) => return refuse(StatusCode::FORBIDDEN, "the credential is not for inference"),
            Err(e) => return refuse(StatusCode::UNAUTHORIZED, &e),
        };
        let agent = claims.agent;
        let model = body
            .get("model")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_string();
        let detail = serde_json::to_vec(&body).unwrap_or_default();
        let ceiling_units = body
            .get("max_tokens")
            .and_then(Json::as_u64)
            .unwrap_or(self.pricing.default_max_units);
        let payee = hex::encode(self.pricing.payee.as_bytes());
        let proposed = |amount: u128| Proposed {
            operation: "inference".to_string(),
            counterparty: payee.clone(),
            amount,
            model: Some(model.clone()),
            ..Default::default()
        };
        let ceiling = self.pricing.per_unit.saturating_mul(ceiling_units as u128);
        if let Err(r) = self.authority.check(&agent, &proposed(ceiling), now) {
            self.record(
                &agent,
                &model,
                ActionOutcome::Refused(r.0.clone()),
                &detail,
                None,
            );
            let status = if r.0 == crate::authority::REVOKED {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::FORBIDDEN
            };
            return refuse(status, &r.0);
        }
        let (mut response, units) = match self.route.complete(&body).await {
            Ok(r) => r,
            Err(e) => {
                self.record(
                    &agent,
                    &model,
                    ActionOutcome::Refused(e.clone()),
                    &detail,
                    None,
                );
                return refuse(StatusCode::BAD_GATEWAY, &e);
            }
        };
        let amount = self
            .pricing
            .per_unit
            .saturating_mul(units.min(ceiling_units) as u128);
        let now = crate::now_ms();
        let settled = self
            .authority
            .authorize(&agent, &proposed(amount), now)
            .and_then(|()| {
                let reference = format!("{}:{}", claims.jti, uuid::Uuid::new_v4());
                self.authority
                    .settle(&agent, &self.pricing.payee, amount, &reference)
            });
        let tx = match settled {
            Ok(tx) => tx,
            Err(r) => {
                self.record(
                    &agent,
                    &model,
                    ActionOutcome::Refused(r.0.clone()),
                    &detail,
                    None,
                );
                return refuse(StatusCode::PAYMENT_REQUIRED, &r.0);
            }
        };
        let full = [
            detail.as_slice(),
            &serde_json::to_vec(&response).unwrap_or_default(),
        ]
        .concat();
        let Some(receipt) = self.record(
            &agent,
            &model,
            ActionOutcome::Allowed,
            &full,
            Some(tx.clone()),
        ) else {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the receipt was not signed",
            );
        };
        if let Some(o) = response.as_object_mut() {
            o.insert(
                "tenzro".into(),
                json!({"settlement": tx, "units": units, "amount": amount.to_string()}),
            );
        }
        let header = B64.encode(serde_json::to_vec(&receipt).unwrap_or_default());
        let mut out = axum::Json(response).into_response();
        if let Ok(v) = header.parse() {
            out.headers_mut().insert(RECEIPT_HEADER, v);
        }
        out
    }
}

async fn chat(
    State(p): State<Arc<TenzroProvider>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Json>,
) -> Response {
    p.serve(&headers, body).await
}

async fn models(State(p): State<Arc<TenzroProvider>>, headers: HeaderMap) -> Response {
    let ok = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|t| crate::token::verify(&p.issuer, t.trim(), crate::now_ms()).is_ok());
    if !ok {
        return refuse(StatusCode::UNAUTHORIZED, "no valid Tenzro credential");
    }
    axum::Json(json!({"object": "list", "data": []})).into_response()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::authority::StateAuthority;
    use crate::credential_driver::tests::{ROOT, agent, fixture};
    use crate::token::Claims;
    use tower::ServiceExt;

    /// A fixed upstream reporting `units` per call.
    pub struct Fixed(pub u64);

    #[async_trait::async_trait]
    impl Route for Fixed {
        async fn complete(&self, request: &Json) -> Result<(Json, u64), String> {
            Ok((
                json!({"object": "chat.completion", "model": request["model"],
                       "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}],
                       "usage": {"total_tokens": self.0}}),
                self.0,
            ))
        }
    }

    fn provider(
        cap: &str,
    ) -> (
        Arc<TenzroProvider>,
        Arc<StateAuthority>,
        Arc<tenzro_crypto::batch::ImmediateRecordSigner>,
        Arc<RecordLog>,
    ) {
        let (a, signer, records) = fixture(&["inference"]);
        let mut t = crate::credential_driver::tests::terms(&["inference"]);
        t.delegation_scope.max_transaction_value = Some(cap.into());
        t.delegation_scope.allowed_models = vec!["tenzro/small".into()];
        a.install_terms(&agent(), t);
        a.fund(StateAuthority::wallet(&agent()), 10_000);
        let p = TenzroProvider::new(
            a.clone(),
            signer.identity().clone(),
            records.clone(),
            Arc::new(Fixed(30)),
            Pricing {
                per_unit: 2,
                default_max_units: 100,
                payee: Address::new([9; 32]),
            },
        );
        (p, a, signer, records)
    }

    fn credential(signer: &tenzro_crypto::batch::ImmediateRecordSigner, scope: &str) -> String {
        let now = crate::now_ms();
        crate::token::mint(
            signer,
            &Claims {
                agent: agent(),
                provider: "tenzro".into(),
                key: "TENZRO_AGENT_TOKEN".into(),
                scope: scope.into(),
                iat_ms: now,
                exp_ms: now + 60_000,
                jti: "j1".into(),
            },
        )
        .unwrap()
    }

    async fn call(
        p: &Arc<TenzroProvider>,
        bearer: Option<&str>,
        model: &str,
    ) -> axum::http::Response<axum::body::Body> {
        let mut b = axum::http::Request::post("/v1/chat/completions")
            .header("content-type", "application/json");
        if let Some(t) = bearer {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        let body = json!({"model": model, "messages": [{"role": "user", "content": "hi"}], "max_tokens": 50});
        p.clone()
            .router()
            .oneshot(b.body(axum::body::Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_call_settles_per_unit_against_a_signed_receipt() {
        let (p, a, signer, records) = provider("1000");
        let r = call(&p, Some(&credential(&signer, "inference")), "tenzro/small").await;
        assert_eq!(r.status(), StatusCode::OK);
        let header = r.headers()[RECEIPT_HEADER].to_str().unwrap().to_string();
        // 30 units at 2 each.
        assert_eq!(a.balance(&StateAuthority::wallet(&agent())), 10_000 - 60);
        assert_eq!(a.balance(&Address::new([9; 32])), 60);
        let receipt: SignedAuditEntry =
            serde_json::from_slice(&B64.decode(&header).unwrap()).unwrap();
        let entries =
            crate::records::verify_session(records.identity(), &records.entries(&agent())).unwrap();
        assert_eq!(entries.last().unwrap(), &receipt.entry().unwrap());
        assert_eq!(
            receipt_reference(&header),
            entries.last().unwrap().linked_tx.clone().unwrap()
        );
    }

    #[tokio::test]
    async fn calls_without_a_valid_credential_or_outside_the_terms_are_refused() {
        let (p, a, signer, _) = provider("1000");
        assert_eq!(
            call(&p, None, "tenzro/small").await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(&p, Some("sk-raw"), "tenzro/small").await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(&p, Some(&credential(&signer, "pay")), "tenzro/small")
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(&p, Some(&credential(&signer, "inference")), "other/model")
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(a.balance(&StateAuthority::wallet(&agent())), 10_000);
    }

    #[tokio::test]
    async fn a_call_whose_ceiling_exceeds_the_per_call_cap_does_not_run() {
        let (p, a, signer, _) = provider("99");
        assert_eq!(
            call(&p, Some(&credential(&signer, "inference")), "tenzro/small")
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(a.balance(&StateAuthority::wallet(&agent())), 10_000);
    }

    #[tokio::test]
    async fn revocation_stops_an_outstanding_credential() {
        let (p, a, signer, _) = provider("1000");
        let t = credential(&signer, "inference");
        assert_eq!(
            call(&p, Some(&t), "tenzro/small").await.status(),
            StatusCode::OK
        );
        a.revoke(ROOT, "kill switch");
        assert_eq!(
            call(&p, Some(&t), "tenzro/small").await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
}
