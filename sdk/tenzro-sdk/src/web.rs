//! Machine payments on the web: the publisher gate and the paying client.
//!
//! A publisher lists paid paths with a USD price; the gate answers an agent's
//! request for one with 402 and the x402 requirements, and lets the request
//! through only after a facilitator has settled the payment, so a handler
//! never runs unpaid. The same policy renders the machine-readable licence
//! (RSL), the robots.txt `License:` line and the `Content-Usage` (AIPREF)
//! header. A delegated agent pays from a channel its wallet funded: its
//! serving node signs each voucher with its hardware key for the agent, and
//! the ledger honours it only within the agent's Terms.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use base64::Engine as _;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use crate::error::{SdkError, SdkResult};
use crate::rpc::RpcClient;

/// Header carrying the requirements on a 402.
pub const PAYMENT_REQUIRED_HEADER: &str = "PAYMENT-REQUIRED";
/// Header carrying the payer's payload on the retried request.
pub const PAYMENT_SIGNATURE_HEADER: &str = "PAYMENT-SIGNATURE";
/// Header carrying the settlement on a paid response.
pub const PAYMENT_RESPONSE_HEADER: &str = "PAYMENT-RESPONSE";
/// The protocol version Tenzro facilitators speak.
pub const X402_VERSION: u32 = 2;
/// The default scheme order: a channel voucher, then a signed payment.
pub const DEFAULT_SCHEMES: [&str; 2] = ["batch-settlement", "tenzro-hybrid"];

/// One way to pay, as a resource server offers it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirement {
    pub scheme: String,
    pub network: String,
    pub amount: String,
    pub asset: String,
    pub pay_to: String,
    pub max_timeout_seconds: u64,
    #[serde(default)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl PaymentRequirement {
    /// The challenge id the requirement names.
    pub fn challenge_id(&self) -> Option<&str> {
        self.extra.get("challengeId").and_then(|v| v.as_str())
    }
}

/// The resource a requirement set is for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceInfo {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// The body of `PAYMENT-REQUIRED`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequired {
    pub x402_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub resource: ResourceInfo,
    pub accepts: Vec<PaymentRequirement>,
}

/// A settlement as a facilitator reports it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettlementResponse {
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    #[serde(default)]
    pub transaction: String,
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
}

/// Base64 (standard, padded), as every x402 header carries JSON.
pub fn encode_header(text: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(text.as_bytes())
}

/// The JSON text a base64 header carries.
pub fn decode_header(value: &str) -> SdkResult<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|e| SdkError::InvalidParameter(format!("x402 header is not base64: {e}")))?;
    String::from_utf8(bytes)
        .map_err(|e| SdkError::InvalidParameter(format!("x402 header is not UTF-8: {e}")))
}

/// The Tenzro network name of chain `chain_id`.
pub fn tenzro_network(chain_id: u64) -> String {
    format!("tenzro:{chain_id}")
}

// ---------------------------------------------------------------- policy

/// One paid path.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaidRoute {
    /// An exact path, or a prefix ending in `*`.
    pub path: String,
    /// Price per request, USD micro-units.
    pub usd_e6: u64,
    /// Accepted schemes, most preferred first; empty means [`DEFAULT_SCHEMES`].
    #[serde(default)]
    pub schemes: Vec<String>,
    /// The asset paid; `TNZO` when absent, priced at the consensus rate.
    #[serde(default)]
    pub asset: Option<String>,
    /// A fixed amount in the asset's smallest unit, instead of quoting.
    #[serde(default)]
    pub amount: Option<String>,
    /// Uses the licence permits (RSL usage tokens).
    #[serde(default)]
    pub permits: Vec<String>,
    /// Uses it prohibits.
    #[serde(default)]
    pub prohibits: Vec<String>,
    /// What a payment licenses (RSL payment type); `use` when absent.
    #[serde(default)]
    pub licence_type: Option<String>,
    /// The `Content-Usage` header value served with the path.
    #[serde(default)]
    pub content_usage: Option<String>,
    /// Shown to payers with the requirement.
    #[serde(default)]
    pub description: Option<String>,
}

impl PaidRoute {
    fn schemes(&self) -> Vec<String> {
        if self.schemes.is_empty() {
            DEFAULT_SCHEMES.iter().map(|s| s.to_string()).collect()
        } else {
            self.schemes.clone()
        }
    }

    fn asset(&self) -> &str {
        self.asset.as_deref().unwrap_or("TNZO")
    }
}

/// A publisher's whole policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublisherPolicy {
    pub chain_id: u64,
    /// The Tenzro account paid (hex).
    pub pay_to: String,
    /// Base URL of the x402 facilitator.
    pub facilitator: String,
    pub routes: Vec<PaidRoute>,
    /// Charge requests that carry no agent signature too.
    #[serde(default)]
    pub charge_unsigned: bool,
    /// Seconds a payer has to answer; 300 when absent.
    #[serde(default)]
    pub max_timeout_seconds: Option<u64>,
}

/// The route `path` falls under: an exact path wins, then the longest prefix.
pub fn match_route<'a>(routes: &'a [PaidRoute], path: &str) -> Option<&'a PaidRoute> {
    routes
        .iter()
        .find(|r| !r.path.ends_with('*') && r.path == path)
        .or_else(|| {
            routes
                .iter()
                .filter(|r| r.path.ends_with('*') && path.starts_with(&r.path[..r.path.len() - 1]))
                .max_by_key(|r| r.path.len())
        })
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn usd(usd_e6: u64) -> String {
    let frac = format!("{:06}", usd_e6 % 1_000_000);
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() {
        (usd_e6 / 1_000_000).to_string()
    } else {
        format!("{}.{frac}", usd_e6 / 1_000_000)
    }
}

/// The policy as an RSL licence document, its content URLs on `origin`.
pub fn rsl_xml(policy: &PublisherPolicy, origin: &str) -> String {
    let base = origin.trim_end_matches('/');
    let mut out = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<rsl xmlns=\"https://rslstandard.org/rsl\">\n",
    );
    for r in &policy.routes {
        out += &format!(
            "  <content url=\"{}\">\n    <license>\n",
            xml(&format!("{base}{}", r.path))
        );
        if !r.permits.is_empty() {
            out += &format!(
                "      <permits type=\"usage\">{}</permits>\n",
                xml(&r.permits.join(" "))
            );
        }
        if !r.prohibits.is_empty() {
            out += &format!(
                "      <prohibits type=\"usage\">{}</prohibits>\n",
                xml(&r.prohibits.join(" "))
            );
        }
        out += &format!(
            "      <payment type=\"{}\">\n        <amount currency=\"USD\">{}</amount>\n      </payment>\n    </license>\n  </content>\n",
            r.licence_type.as_deref().unwrap_or("use"),
            usd(r.usd_e6)
        );
    }
    out + "</rsl>\n"
}

/// The robots.txt line pointing crawlers at the licence.
pub fn robots_license_line(origin: &str) -> String {
    format!("License: {}/license.xml", origin.trim_end_matches('/'))
}

// ---------------------------------------------------------------- gate

/// Settles a payment: the facilitator's `/settle`, given the request body.
pub trait Facilitator: Send + Sync {
    fn settle(&self, body: String) -> BoxFuture<'_, SdkResult<SettlementResponse>>;
}

/// A facilitator over HTTP.
pub struct HttpFacilitator {
    base: String,
    http: reqwest::Client,
}

impl HttpFacilitator {
    pub fn new(base: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }
}

impl Facilitator for HttpFacilitator {
    fn settle(&self, body: String) -> BoxFuture<'_, SdkResult<SettlementResponse>> {
        Box::pin(async move {
            self.http
                .post(format!("{}/settle", self.base))
                .header("content-type", "application/json")
                .body(body)
                .send()
                .await
                .map_err(|e| SdkError::ConnectionError(e.to_string()))?
                .json()
                .await
                .map_err(|e| SdkError::SettlementError(e.to_string()))
        })
    }
}

/// Prices USD micro-units in TNZO base units (`tenzro_quotePayment`).
pub type Quote = Arc<dyn Fn(u64) -> BoxFuture<'static, SdkResult<u128>> + Send + Sync>;

/// A quote from a node's consensus rate.
pub fn node_quote(rpc: Arc<RpcClient>) -> Quote {
    Arc::new(move |usd_e6| {
        let rpc = rpc.clone();
        Box::pin(async move {
            let v: serde_json::Value = rpc
                .call(
                    "tenzro_quotePayment",
                    serde_json::json!({ "usd_e6": usd_e6 }),
                )
                .await?;
            v["assets"][0]["amount"]
                .as_str()
                .and_then(|a| a.parse().ok())
                .ok_or_else(|| SdkError::RpcError("quotePayment returned no TNZO amount".into()))
        })
    })
}

/// What the gate decided for one request.
#[derive(Debug, Clone, PartialEq)]
pub enum GateDecision {
    /// Serve it; the path is free or the request is a person's.
    Serve { content_usage: Option<String> },
    /// Serve it; it was paid. `payment_response` is the `PAYMENT-RESPONSE` value.
    Paid {
        payment_response: String,
        content_usage: Option<String>,
    },
    /// Answer 402 with `body` and `PAYMENT-REQUIRED: header`.
    PaymentRequired {
        body: String,
        header: String,
        content_usage: Option<String>,
    },
    /// No price is available now; answer 503.
    Unavailable,
}

/// The publisher gate.
pub struct PublisherGate {
    policy: PublisherPolicy,
    quote: Option<Quote>,
    facilitator: Arc<dyn Facilitator>,
    quote_ttl: Duration,
    prices: Mutex<HashMap<String, Vec<(u128, Instant)>>>,
}

impl PublisherGate {
    pub fn new(
        policy: PublisherPolicy,
        facilitator: Arc<dyn Facilitator>,
        quote: Option<Quote>,
    ) -> Self {
        Self {
            policy,
            quote,
            facilitator,
            quote_ttl: Duration::from_secs(60),
            prices: Mutex::new(HashMap::new()),
        }
    }

    /// Decide for a request to `url` with `headers`: whether it is free,
    /// paid (settled before this returns), or must pay first.
    pub async fn decide(&self, url: &str, headers: &http::HeaderMap) -> GateDecision {
        let path = url
            .split("://")
            .nth(1)
            .and_then(|r| r.find('/').map(|i| &r[i..]))
            .unwrap_or("/");
        let path = path.split(['?', '#']).next().unwrap_or(path);
        let Some(route) = match_route(&self.policy.routes, path) else {
            return GateDecision::Serve {
                content_usage: None,
            };
        };
        let usage = route.content_usage.clone();
        let payment = headers
            .get(PAYMENT_SIGNATURE_HEADER)
            .and_then(|v| v.to_str().ok());
        let signed = headers.contains_key("signature-input") && headers.contains_key("signature");
        let Some(payment) = payment else {
            if !self.policy.charge_unsigned && !signed {
                return GateDecision::Serve {
                    content_usage: usage,
                };
            }
            return self.required(url, route, None).await;
        };
        let Ok(text) = decode_header(payment) else {
            return self.required(url, route, Some("invalid_payload")).await;
        };
        let Ok(payload) = serde_json::from_str::<serde_json::Value>(&text) else {
            return self.required(url, route, Some("invalid_payload")).await;
        };
        if payload.is_null() {
            return self.required(url, route, Some("invalid_payload")).await;
        }
        // A payload naming no requirement, or one of another shape, accepts nothing offered.
        let accepted: Option<PaymentRequirement> =
            serde_json::from_value(payload["accepted"].clone()).ok();
        let Some(accepted) = accepted.filter(|a| a.challenge_id().is_some()) else {
            return self
                .required(url, route, Some("requirement_not_offered"))
                .await;
        };
        if !self.offers(route, &accepted).await {
            return self
                .required(url, route, Some("requirement_not_offered"))
                .await;
        }
        // Settle before the handler runs; the payload is forwarded as sent.
        let body = format!(
            "{{\"x402Version\":{X402_VERSION},\"paymentPayload\":{text},\"paymentRequirements\":{}}}",
            serde_json::to_string(&accepted).unwrap_or_default()
        );
        match self.facilitator.settle(body).await {
            Ok(s) if s.success => GateDecision::Paid {
                payment_response: encode_header(&serde_json::to_string(&s).unwrap_or_default()),
                content_usage: usage,
            },
            Ok(s) => {
                self.required(
                    url,
                    route,
                    Some(s.error_reason.as_deref().unwrap_or("settlement_failed")),
                )
                .await
            }
            Err(_) => {
                self.required(url, route, Some("facilitator_unreachable"))
                    .await
            }
        }
    }

    /// The requirements `route` offers now, one per accepted scheme.
    pub async fn requirements(&self, route: &PaidRoute) -> SdkResult<Vec<PaymentRequirement>> {
        let amount = self.price(route).await?.to_string();
        let challenge_id = uuid::Uuid::new_v4().to_string();
        Ok(route
            .schemes()
            .into_iter()
            .map(|scheme| {
                let mut extra = serde_json::Map::new();
                extra.insert("challengeId".into(), challenge_id.clone().into());
                extra.insert("chain_id".into(), self.policy.chain_id.into());
                extra.insert("usd_e6".into(), route.usd_e6.into());
                PaymentRequirement {
                    scheme,
                    network: tenzro_network(self.policy.chain_id),
                    amount: amount.clone(),
                    asset: route.asset().to_string(),
                    pay_to: self.policy.pay_to.clone(),
                    max_timeout_seconds: self.policy.max_timeout_seconds.unwrap_or(300),
                    extra,
                }
            })
            .collect())
    }

    async fn required(&self, url: &str, route: &PaidRoute, error: Option<&str>) -> GateDecision {
        let Ok(accepts) = self.requirements(route).await else {
            return GateDecision::Unavailable;
        };
        let required = PaymentRequired {
            x402_version: X402_VERSION,
            error: error.map(str::to_string),
            resource: ResourceInfo {
                url: url.to_string(),
                description: route.description.clone(),
            },
            accepts,
        };
        let body = serde_json::to_string(&required).unwrap_or_default();
        GateDecision::PaymentRequired {
            header: encode_header(&body),
            body,
            content_usage: route.content_usage.clone(),
        }
    }

    async fn offers(&self, route: &PaidRoute, r: &PaymentRequirement) -> bool {
        let norm = |s: &str| s.trim_start_matches("0x").to_ascii_lowercase();
        if r.challenge_id().is_none()
            || !route
                .schemes()
                .iter()
                .any(|s| s.eq_ignore_ascii_case(&r.scheme))
            || r.network != tenzro_network(self.policy.chain_id)
            || norm(&r.pay_to) != norm(&self.policy.pay_to)
            || !r.asset.eq_ignore_ascii_case(route.asset())
        {
            return false;
        }
        let Ok(paid) = r.amount.parse::<u128>() else {
            return false;
        };
        let Ok(current) = self.price(route).await else {
            return false;
        };
        if route.amount.is_some() {
            return paid >= current;
        }
        let prices = self.prices.lock().unwrap();
        prices
            .get(&route.path)
            .map(|p| p.iter().any(|(a, _)| paid >= *a))
            .unwrap_or(false)
    }

    /// The route's price, quoted at most once per TTL; the last two quotes stay acceptable.
    async fn price(&self, route: &PaidRoute) -> SdkResult<u128> {
        if let Some(a) = &route.amount {
            return a.parse().map_err(|_| {
                SdkError::InvalidConfiguration(format!("route {} amount", route.path))
            });
        }
        if let Some((a, _)) = self.prices.lock().unwrap().get(&route.path).and_then(|p| {
            p.iter()
                .find(|(_, at)| at.elapsed() < self.quote_ttl)
                .copied()
        }) {
            return Ok(a);
        }
        let quote = self.quote.as_ref().ok_or_else(|| {
            SdkError::InvalidConfiguration(format!(
                "route {} is priced in USD and the gate has no quote",
                route.path
            ))
        })?;
        let amount = quote(route.usd_e6).await?;
        let mut prices = self.prices.lock().unwrap();
        let seen = prices.entry(route.path.clone()).or_default();
        seen.insert(0, (amount, Instant::now()));
        seen.truncate(2);
        Ok(amount)
    }
}

/// The gate as a tower layer: an unpaid request never reaches the inner
/// service.
#[derive(Clone)]
pub struct PublisherGateLayer {
    gate: Arc<PublisherGate>,
}

impl PublisherGateLayer {
    pub fn new(gate: Arc<PublisherGate>) -> Self {
        Self { gate }
    }
}

impl<S> tower::Layer<S> for PublisherGateLayer {
    type Service = PublisherGateService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        PublisherGateService {
            gate: self.gate.clone(),
            inner,
        }
    }
}

/// The service [`PublisherGateLayer`] wraps around an inner one.
#[derive(Clone)]
pub struct PublisherGateService<S> {
    gate: Arc<PublisherGate>,
    inner: S,
}

impl<S, ReqB, ResB> tower::Service<http::Request<ReqB>> for PublisherGateService<S>
where
    S: tower::Service<http::Request<ReqB>, Response = http::Response<ResB>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    ReqB: Send + 'static,
    ResB: From<String> + Send + 'static,
{
    type Response = http::Response<ResB>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<ReqB>) -> Self::Future {
        let gate = self.gate.clone();
        // The ready inner service goes with this call; a fresh clone stays.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            let host = req
                .headers()
                .get(http::header::HOST)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("localhost");
            let url = format!(
                "https://{host}{}",
                req.uri()
                    .path_and_query()
                    .map(|p| p.as_str())
                    .unwrap_or("/")
            );
            let set = |res: &mut http::Response<ResB>, name: &str, value: Option<String>| {
                if let Some(v) = value.and_then(|v| http::HeaderValue::from_str(&v).ok())
                    && let Ok(n) = http::HeaderName::from_bytes(name.as_bytes())
                {
                    res.headers_mut().insert(n, v);
                }
            };
            match gate.decide(&url, req.headers()).await {
                GateDecision::Serve { content_usage } => {
                    let mut res = inner.call(req).await?;
                    set(&mut res, "content-usage", content_usage);
                    Ok(res)
                }
                GateDecision::Paid {
                    payment_response,
                    content_usage,
                } => {
                    let mut res = inner.call(req).await?;
                    set(&mut res, PAYMENT_RESPONSE_HEADER, Some(payment_response));
                    set(&mut res, "content-usage", content_usage);
                    Ok(res)
                }
                GateDecision::PaymentRequired {
                    body,
                    header,
                    content_usage,
                } => {
                    let mut res = http::Response::new(ResB::from(body));
                    *res.status_mut() = http::StatusCode::PAYMENT_REQUIRED;
                    set(&mut res, "content-type", Some("application/json".into()));
                    set(&mut res, PAYMENT_REQUIRED_HEADER, Some(header));
                    set(&mut res, "content-usage", content_usage);
                    Ok(res)
                }
                GateDecision::Unavailable => {
                    let mut res = http::Response::new(ResB::from(
                        "payment required, but no price is available".to_string(),
                    ));
                    *res.status_mut() = http::StatusCode::SERVICE_UNAVAILABLE;
                    Ok(res)
                }
            }
        })
    }
}

// ---------------------------------------------------------------- payer

/// Pays requirements it supports.
pub trait Payer: Send + Sync {
    fn supports(&self, r: &PaymentRequirement) -> bool;
    /// The payload's `payload` field, as JSON text.
    fn pay<'a>(
        &'a self,
        r: &'a PaymentRequirement,
        resource: &'a ResourceInfo,
    ) -> BoxFuture<'a, SdkResult<String>>;
}

/// The `PAYMENT-SIGNATURE` value for `requirement`, paid by `payer`.
pub async fn payment_header(
    payer: &dyn Payer,
    required: &PaymentRequired,
    requirement: &PaymentRequirement,
) -> SdkResult<String> {
    let payload = payer.pay(requirement, &required.resource).await?;
    let text = format!(
        "{{\"x402Version\":{X402_VERSION},\"resource\":{},\"accepted\":{},\"payload\":{payload}}}",
        serde_json::to_string(&required.resource)
            .map_err(|e| SdkError::InvalidParameter(e.to_string()))?,
        serde_json::to_string(requirement)
            .map_err(|e| SdkError::InvalidParameter(e.to_string()))?,
    );
    Ok(encode_header(&text))
}

/// A client that pays: it answers 402 by paying one offered requirement
/// within `max_amount` and retrying, and pays a path it paid before up front.
pub struct PayingClient {
    http: reqwest::Client,
    payer: Arc<dyn Payer>,
    max_amount: u128,
    known: Mutex<HashMap<String, (PaymentRequired, PaymentRequirement)>>,
}

impl PayingClient {
    pub fn new(http: reqwest::Client, payer: Arc<dyn Payer>, max_amount: u128) -> Self {
        Self {
            http,
            payer,
            max_amount,
            known: Mutex::new(HashMap::new()),
        }
    }

    /// GET `url` with `headers` (an agent's message signature, for example), paying if asked.
    pub async fn get(
        &self,
        url: &str,
        headers: reqwest::header::HeaderMap,
    ) -> SdkResult<reqwest::Response> {
        let key = url.split(['?', '#']).next().unwrap_or(url).to_string();
        let send = |extra: Option<String>| {
            let mut h = headers.clone();
            if let Some(v) = extra.and_then(|v| reqwest::header::HeaderValue::from_str(&v).ok()) {
                h.insert(PAYMENT_SIGNATURE_HEADER, v);
            }
            self.http.get(url).headers(h).send()
        };
        let prior = self.known.lock().unwrap().get(&key).cloned();
        if let Some((required, mut requirement)) = prior {
            requirement.extra.insert(
                "challengeId".into(),
                uuid::Uuid::new_v4().to_string().into(),
            );
            let res = send(Some(
                payment_header(self.payer.as_ref(), &required, &requirement).await?,
            ))
            .await
            .map_err(|e| SdkError::ConnectionError(e.to_string()))?;
            if res.status() != reqwest::StatusCode::PAYMENT_REQUIRED {
                return Ok(res);
            }
            self.known.lock().unwrap().remove(&key);
        }
        let first = send(None)
            .await
            .map_err(|e| SdkError::ConnectionError(e.to_string()))?;
        if first.status() != reqwest::StatusCode::PAYMENT_REQUIRED {
            return Ok(first);
        }
        let Some(header) = first
            .headers()
            .get(PAYMENT_REQUIRED_HEADER)
            .and_then(|v| v.to_str().ok())
        else {
            return Ok(first);
        };
        let required: PaymentRequired = serde_json::from_str(&decode_header(header)?)
            .map_err(|e| SdkError::InvalidParameter(format!("PAYMENT-REQUIRED: {e}")))?;
        let Some(requirement) = required
            .accepts
            .iter()
            .find(|r| {
                self.payer.supports(r)
                    && r.amount.parse::<u128>().is_ok_and(|a| a <= self.max_amount)
            })
            .cloned()
        else {
            return Ok(first);
        };
        let paid = send(Some(
            payment_header(self.payer.as_ref(), &required, &requirement).await?,
        ))
        .await
        .map_err(|e| SdkError::ConnectionError(e.to_string()))?;
        if paid.status() != reqwest::StatusCode::PAYMENT_REQUIRED {
            self.known
                .lock()
                .unwrap()
                .insert(key, (required, requirement));
        }
        Ok(paid)
    }
}

/// The voucher a serving node signed for an agent (`tenzro_agentVoucher`).
#[derive(Debug, Clone, Deserialize)]
pub struct SignedAgentVoucher {
    /// The serving node's composite signature (hardware P-256 leg, plus the
    /// ML-DSA-65 leg when it has one), as JSON.
    pub signature: serde_json::Value,
    pub agent: AgentVoucherSigner,
}

/// Who signed an agent's voucher.
#[derive(Debug, Clone, Deserialize)]
pub struct AgentVoucherSigner {
    pub agent_did: String,
    pub machine_did: String,
    pub as_of_ms: u64,
}

#[derive(Serialize)]
struct Credential<'a> {
    credential_id: &'a str,
    challenge_id: &'a str,
    protocol: &'a str,
    payer_did: &'a str,
    payer_address: &'a str,
    amount: u128,
    asset: &'a str,
    signature: &'a serde_json::Value,
    extra: CredentialExtra<'a>,
}

#[derive(Serialize)]
struct CredentialExtra<'a> {
    escrow_id: String,
    cumulative_amount: String,
    agent_did: &'a str,
    machine_did: &'a str,
    as_of_ms: String,
}

/// The credential a facilitator takes for an agent's voucher, as JSON text.
pub fn agent_voucher_credential(
    r: &PaymentRequirement,
    channel_id: &str,
    cumulative: u128,
    charge: u128,
    voucher: &SignedAgentVoucher,
    credential_id: &str,
) -> SdkResult<String> {
    serde_json::to_string(&Credential {
        credential_id,
        challenge_id: r.challenge_id().unwrap_or_default(),
        protocol: "x402",
        payer_did: &voucher.agent.agent_did,
        payer_address: "",
        amount: charge,
        asset: &r.asset,
        signature: &voucher.signature,
        extra: CredentialExtra {
            escrow_id: channel_id.trim_start_matches("0x").to_string(),
            cumulative_amount: cumulative.to_string(),
            agent_did: &voucher.agent.agent_did,
            machine_did: &voucher.agent.machine_did,
            as_of_ms: voucher.agent.as_of_ms.to_string(),
        },
    })
    .map_err(|e| SdkError::InvalidParameter(e.to_string()))
}

/// A delegated agent paying from its channel to one payee.
pub struct AgentChannelPayer {
    rpc: Arc<RpcClient>,
    chain_id: u64,
    channel_id: String,
    pay_to: String,
    cumulative: tokio::sync::Mutex<u128>,
}

impl AgentChannelPayer {
    /// `rpc` reaches one of the agent's serving nodes with the agent's
    /// credential; `spent` is what earlier vouchers on the channel cover.
    pub fn new(
        rpc: Arc<RpcClient>,
        chain_id: u64,
        channel_id: &str,
        pay_to: &str,
        spent: u128,
    ) -> Self {
        Self {
            rpc,
            chain_id,
            channel_id: channel_id.to_string(),
            pay_to: pay_to.to_string(),
            cumulative: tokio::sync::Mutex::new(spent),
        }
    }
}

impl Payer for AgentChannelPayer {
    fn supports(&self, r: &PaymentRequirement) -> bool {
        let norm = |s: &str| s.trim_start_matches("0x").to_ascii_lowercase();
        r.scheme == "batch-settlement"
            && r.network == tenzro_network(self.chain_id)
            && norm(&r.pay_to) == norm(&self.pay_to)
    }

    fn pay<'a>(
        &'a self,
        r: &'a PaymentRequirement,
        _resource: &'a ResourceInfo,
    ) -> BoxFuture<'a, SdkResult<String>> {
        Box::pin(async move {
            let charge: u128 = r
                .amount
                .parse()
                .map_err(|_| SdkError::InvalidParameter("amount".into()))?;
            let mut cumulative = self.cumulative.lock().await;
            let next = *cumulative + charge;
            let v: serde_json::Value = self
                .rpc
                .call(
                    "tenzro_agentVoucher",
                    serde_json::json!({ "channel_id": self.channel_id, "cumulative_amount": next.to_string() }),
                )
                .await?;
            let voucher: SignedAgentVoucher = serde_json::from_value(v["voucher"].clone())
                .map_err(|e| SdkError::RpcError(format!("agentVoucher: {e}")))?;
            *cumulative = next;
            agent_voucher_credential(
                r,
                &self.channel_id,
                next,
                charge,
                &voucher,
                &uuid::Uuid::new_v4().to_string(),
            )
        })
    }
}
