//! Axum middleware for payment-gated endpoints
//!
//! Provides middleware that intercepts requests to payment-gated API endpoints,
//! returning HTTP 402 challenges and verifying payment credentials.

use crate::challenge_store::ChallengeStore;
use crate::traits::PaymentGateway;
use crate::types::PaymentCredential;
use axum::{
    body::Body,
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use tracing::{debug, warn};

/// Configuration for the payment gate middleware
#[derive(Debug, Clone)]
pub struct PaymentGateConfig {
    /// Default payment amount for gated endpoints
    pub default_amount: u128,
    /// Default asset for payment
    pub default_asset: String,
    /// Recipient address for payments
    pub recipient: String,
    /// Default protocol to use
    pub default_protocol: String,
}

impl Default for PaymentGateConfig {
    fn default() -> Self {
        Self {
            default_amount: 0,
            default_asset: "USDC".to_string(),
            recipient: String::new(),
            default_protocol: "mpp".to_string(),
        }
    }
}

/// Access decision for an inference request, returned by an
/// [`InferenceAdmission`] before the payment gate runs.
///
/// The gate consults this first so that pre-paid (subscription) and
/// pre-authorized (rental) credentials skip payment entirely, open
/// on-demand models fall through to the x402 challenge, and gated or
/// private models are refused *without* issuing a pay-per-call challenge.
#[derive(Debug, Clone)]
pub enum InferenceAccess {
    /// A valid pre-paid (subscription) or pre-authorized (rental) credential — skip payment entirely.
    Allow,
    /// No pre-paid credential; the model is open on-demand (or operator-enabled fallback) — proceed with x402.
    NeedPayment,
    /// Refuse without issuing an x402 challenge (gated model without credential, or private/unknown). Carries HTTP status + message.
    Refuse(u16, String),
}

/// Decides inference access from request headers + the requested model,
/// independently of the payment mechanism.
///
/// Implemented in `tenzro-node` (which knows about access tokens, the
/// admission gate, and served-model visibility); kept as a trait here so
/// `tenzro-payments` does not depend on `tenzro-node`.
pub trait InferenceAdmission: Send + Sync {
    /// Decide access for an inference request. `model_id` is the parsed `model` field of the chat body (None if unparseable).
    fn decide(&self, headers: &axum::http::HeaderMap, model_id: Option<&str>) -> InferenceAccess;
}

/// Payment gate middleware state
///
/// Attach this to Axum router state to enable payment-gated endpoints.
#[derive(Clone)]
pub struct PaymentGateMiddleware {
    /// The payment gateway
    pub gateway: Arc<dyn PaymentGateway>,
    /// Configuration
    pub config: PaymentGateConfig,
    /// Challenge store for looking up challenges during verification
    pub challenge_store: ChallengeStore,
    /// Optional inference admission authorizer. When set, `/chat` requests are
    /// first classified into pre-paid/on-demand/refused before the payment
    /// gate runs (see [`InferenceAdmission`]).
    inference_admission: Option<Arc<dyn InferenceAdmission>>,
    /// When set, an `upto` credential is checked before the request is
    /// served and settled afterwards at the metered cost the handler reports
    /// (see [`METERED_COST_FIELD`]), instead of at the amount the buyer
    /// declared before any work was done.
    metered_settlement: bool,
    /// Signs the usage record behind a metered charge when the challenge
    /// names a meter key.
    meter: Option<Arc<dyn UsageMeter>>,
    /// Challenges whose request is being served under metered settlement.
    /// One credential serves one request at a time: without this, the same
    /// `upto` credential sent concurrently would be served N times and settled
    /// once.
    in_flight: Arc<dashmap::DashSet<String>>,
}

/// The JSON response field an inference handler reports its metered cost in
/// (TNZO wei, decimal string).
pub const METERED_COST_FIELD: &str = "cost_wei";

/// The unit a metered request is recorded in: one request at its metered
/// cost.
pub const METERED_UNIT: &str = "requests";

/// Signs the usage record a metered (`upto`) charge settles against. The x402
/// server implements it with the meter key its `upto` challenges name.
pub trait UsageMeter: Send + Sync {
    /// Charge `credential` for `lines` served against `challenge`: sign a
    /// usage record with the meter and set the credential's charge to it.
    fn meter(
        &self,
        challenge: &crate::types::PaymentChallenge,
        credential: &mut PaymentCredential,
        lines: Vec<crate::metering::UsageLine>,
    ) -> crate::Result<crate::metering::UsageRecord>;
}

/// Largest response body the metered path buffers to read the cost.
const METERED_BODY_LIMIT: usize = 16 * 1024 * 1024;

impl PaymentGateMiddleware {
    /// Creates a new payment gate middleware
    pub fn new(
        gateway: Arc<dyn PaymentGateway>,
        config: PaymentGateConfig,
        challenge_store: ChallengeStore,
    ) -> Self {
        Self {
            gateway,
            config,
            challenge_store,
            inference_admission: None,
            metered_settlement: false,
            meter: None,
            in_flight: Arc::new(dashmap::DashSet::new()),
        }
    }

    /// Settle `upto` credentials at the metered cost of the work they paid
    /// for rather than the amount the buyer declared up front.
    pub fn with_metered_settlement(mut self, on: bool) -> Self {
        self.metered_settlement = on;
        self
    }

    /// Attach the meter that signs usage records for metered charges.
    pub fn with_meter(mut self, meter: Arc<dyn UsageMeter>) -> Self {
        self.meter = Some(meter);
        self
    }

    /// Attach an inference admission authorizer.
    ///
    /// When set, `/chat` requests are classified by the authorizer before the
    /// payment gate runs: pre-paid/pre-authorized credentials bypass payment,
    /// open on-demand models fall through to the x402 challenge, and gated or
    /// private models are refused without a pay-per-call challenge.
    pub fn with_inference_admission(mut self, a: Arc<dyn InferenceAdmission>) -> Self {
        self.inference_admission = Some(a);
        self
    }

    /// Creates a default middleware for testing
    pub fn default_with_gateway(gateway: Arc<dyn PaymentGateway>) -> Self {
        Self::new(gateway, PaymentGateConfig::default(), ChallengeStore::new())
    }
}

/// Axum middleware handler for payment verification
///
/// Reads a payment from the request (see [`credential_from_headers`]). With
/// none, answers 402 with `WWW-Authenticate: Payment`, the challenge as JSON
/// and, for an x402 challenge, `PAYMENT-REQUIRED`. With one, verifies and
/// settles it for this resource and serves the request, adding
/// `PAYMENT-RESPONSE` to an x402 response.
#[cfg(test)]
mod requested_model_tests {
    use super::requested_model;

    #[test]
    fn a_json_body_names_its_model_either_way() {
        assert_eq!(
            requested_model(Some("application/json"), br#"{"model":"m1"}"#).as_deref(),
            Some("m1")
        );
        assert_eq!(
            requested_model(None, br#"{"model_id":"m2","history":[1]}"#).as_deref(),
            Some("m2")
        );
    }

    #[test]
    fn a_multipart_body_names_its_model_in_a_form_field() {
        let body = "--XyZ\r\n\
             Content-Disposition: form-data; name=\"file\"; filename=\"a.wav\"\r\n\
             Content-Type: audio/wav\r\n\r\n\
             RIFF....\r\n\
             --XyZ\r\n\
             Content-Disposition: form-data; name=\"model\"\r\n\r\n\
             whisper-small\r\n\
             --XyZ--\r\n";
        assert_eq!(
            requested_model(Some("multipart/form-data; boundary=XyZ"), body.as_bytes()).as_deref(),
            Some("whisper-small")
        );
        // A field whose name merely contains "model" is not the model.
        let other =
            "--B\r\nContent-Disposition: form-data; name=\"model_hint\"\r\n\r\nx\r\n--B--\r\n";
        assert_eq!(
            requested_model(
                Some("multipart/form-data; boundary=\"B\""),
                other.as_bytes()
            ),
            None
        );
    }
}

#[cfg(test)]
mod refusal_vocabulary_tests {
    use super::{refusal_code, refusal_type};

    /// Only a 402 is about credentials. The whole point of the table is that a
    /// missing model and an off-node model stop reading as a bad key, which is
    /// what sent clients into retry loops and graded models as incapable.
    #[test]
    fn only_payment_required_blames_the_credential() {
        assert_eq!(refusal_type(402), "insufficient_credential");
        assert_eq!(refusal_code(402), "credential_required");

        for status in [400u16, 403, 404, 418, 500] {
            assert_eq!(
                refusal_type(status),
                "invalid_request_error",
                "status {status} must not blame the credential"
            );
            assert_ne!(
                refusal_code(status),
                "credential_required",
                "status {status}"
            );
        }
    }

    #[test]
    fn each_refusal_has_its_own_code() {
        assert_eq!(refusal_code(404), "model_not_served");
        assert_eq!(refusal_code(403), "model_not_offered_off_node");
        assert_eq!(refusal_code(400), "invalid_request");
    }
}

/// Access control for the inference surface, with no payment gate involved.
///
/// A node mounts this whenever it serves models. The payment gate is a separate
/// concern that may or may not be configured on top; whether an operator sells
/// calls has nothing to do with whether a gated model may be reached by someone
/// holding no credential. Before this existed, the RPC router's own comment for
/// the ungated branch read "No payment gate — mount inference routes openly",
/// and it meant it: with no payment recipient configured, `/v1/chat/completions`
/// served `Gated` and `Private` models to anyone who could reach the port, while
/// the JSON-RPC method path on the very same port refused them.
pub async fn inference_admission_handler(
    State(admission): State<std::sync::Arc<dyn InferenceAdmission>>,
    request: Request,
    next: Next,
) -> Result<Response, PaymentGateError> {
    let (classified, decision) = classify(admission.as_ref(), request).await?;
    match decision {
        InferenceAccess::Allow => Ok(next.run(classified).await),
        // Nothing here can collect a payment, so asking for one is a refusal.
        // The alternative — serving it — is what made a priced model free on
        // whichever surface happened to lack a gateway.
        InferenceAccess::NeedPayment => Ok(refusal_response(402, PAYMENT_REQUIRED_NO_GATEWAY)),
        InferenceAccess::Refuse(status, msg) => Ok(refusal_response(status, &msg)),
    }
}

/// Every inference route. The payment gate runs the node's admission check on
/// each of these before any payment logic, so an admitted access token passes and a
/// gated model is refused the same way on every one of them.
pub const INFERENCE_ROUTES: &[&str] = &[
    "/v1/chat/completions",
    "/v1/responses",
    "/tenzro/forecasts",
    "/v1/embeddings",
    "/tenzro/detections",
    "/tenzro/segmentations",
    "/tenzro/video/embeddings",
    "/v1/audio/transcriptions",
];

/// Body ceiling of an inference route whose body is plain JSON: a prompt, a
/// message list, or a numeric series.
pub const JSON_BODY_LIMIT: usize = 2 * 1024 * 1024;

/// Body ceiling of an inference route carrying an image or a video clip,
/// base64 inside JSON or a multipart part.
pub const MEDIA_BODY_LIMIT: usize = 64 * 1024 * 1024;

/// Body ceiling of an audio route: a long recording uploaded whole.
pub const AUDIO_BODY_LIMIT: usize = 128 * 1024 * 1024;

/// Routes whose bodies carry an image or a video clip.
pub const MEDIA_ROUTES: &[&str] = &[
    "/v1/embeddings",
    "/tenzro/detections",
    "/tenzro/segmentations",
    "/tenzro/video/embeddings",
];

/// Routes taking or producing audio.
pub const AUDIO_ROUTES: &[&str] = &[
    "/v1/audio/transcriptions",
    "/v1/audio/speech",
    "/tenzro/realtime/turn",
    "/tenzro/realtime/transcribe",
];

/// The most bytes an inference route accepts in a request body. The node
/// mounts each route under this ceiling, and admission reads no more than it,
/// so a caller with no credential can make the node hold no more than the
/// route itself would.
pub fn inference_body_limit(path: &str) -> usize {
    if AUDIO_ROUTES.contains(&path) {
        AUDIO_BODY_LIMIT
    } else if MEDIA_ROUTES.contains(&path) {
        MEDIA_BODY_LIMIT
    } else {
        JSON_BODY_LIMIT
    }
}

/// Read the request body once, find the model it names, and ask the node's
/// admission check. Returns the request rebuilt around the same body. A body
/// over its route's ceiling is refused before it is read: by its declared
/// length when it has one, and otherwise as soon as the ceiling is passed.
async fn classify(
    admission: &dyn InferenceAdmission,
    request: Request,
) -> Result<(Request, InferenceAccess), PaymentGateError> {
    let limit = inference_body_limit(request.uri().path());
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|len| len > limit as u64) {
        return Err(PaymentGateError::PayloadTooLarge(limit));
    }
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, limit)
        .await
        .map_err(|_| PaymentGateError::PayloadTooLarge(limit))?;
    let content_type = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());
    let model = requested_model(content_type, &bytes);
    let decision = admission.decide(&parts.headers, model.as_deref());
    Ok((Request::from_parts(parts, Body::from(bytes)), decision))
}

/// The model an inference request names: `model` or `model_id` in a JSON body,
/// or a `model` field in a `multipart/form-data` body.
fn requested_model(content_type: Option<&str>, body: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct ModelOnly {
        model: Option<String>,
        model_id: Option<String>,
    }
    if let Ok(m) = serde_json::from_slice::<ModelOnly>(body) {
        return m.model.or(m.model_id);
    }
    let boundary = content_type?
        .split(';')
        .map(str::trim)
        .find_map(|p| p.strip_prefix("boundary="))?
        .trim_matches('"');
    multipart_field(body, boundary, "model")
}

/// The text value of the form field `name` in a `multipart/form-data` body.
fn multipart_field(body: &[u8], boundary: &str, name: &str) -> Option<String> {
    let delimiter = format!("--{boundary}");
    let wanted = format!("name=\"{name}\"");
    let text = String::from_utf8_lossy(body);
    for part in text.split(delimiter.as_str()) {
        let Some((headers, value)) = part.split_once("\r\n\r\n") else {
            continue;
        };
        let names_field = headers.lines().any(|line| {
            line.to_ascii_lowercase()
                .starts_with("content-disposition:")
                && line.split(';').any(|p| p.trim() == wanted)
        });
        if names_field {
            let value = value.strip_suffix("\r\n").unwrap_or(value).trim();
            return (!value.is_empty()).then(|| value.to_string());
        }
    }
    None
}

/// The JSON refusal body every inference route answers with, naming which
/// refusal it is: only a 402 is about credentials, so a 403 or 404 must not
/// read as a bad key.
fn refusal_response(status: u16, msg: &str) -> Response {
    let body = serde_json::json!({
        "error": {
            "message": msg,
            "type": refusal_type(status),
            "code": refusal_code(status),
        }
    })
    .to_string();
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::PAYMENT_REQUIRED);
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::PAYMENT_REQUIRED.into_response())
}

/// The machine-readable code for a refusal, derived from its status.
///
/// One table, exported, because HTTP, JSON-RPC and the iroh overlay all have to
/// answer the same question and were each answering it differently: the HTTP
/// gate said `credential_required` for every refusal including "no such model",
/// the overlay said `forbidden` for all of them, and JSON-RPC said only
/// `-32001`. A caller that switches transport should not have to learn a new
/// vocabulary for the same verdict.
pub fn refusal_code(status: u16) -> &'static str {
    match status {
        402 => "credential_required",
        403 => "model_not_offered_off_node",
        404 => "model_not_served",
        _ => "invalid_request",
    }
}

/// The error family for a refusal. Only a 402 is genuinely about credentials.
pub fn refusal_type(status: u16) -> &'static str {
    match status {
        402 => "insufficient_credential",
        _ => "invalid_request_error",
    }
}

/// What a transport that cannot carry a payment challenge says when the policy
/// asks for one. Refusing is the aligned answer: serving it free instead —
/// which the overlay did — means the same model costs money on one protocol and
/// nothing on another.
pub const PAYMENT_REQUIRED_OFF_HTTP: &str = "payment required for this model; sign in as a caller this node's access policy names, or call the HTTP surface, which can carry an x402 challenge";

/// What the HTTP surface says when the policy asks for payment and this node
/// has no gateway to collect it with.
///
/// Distinct from [`PAYMENT_REQUIRED_OFF_HTTP`], which tells the caller to move
/// to HTTP — useless advice when they are already on it. The operator set a
/// per-use price on a public model without configuring a payment recipient, so
/// the policy asks for money the node cannot take. The caller's way through is
/// to be named by the access policy; the operator's is to finish wiring payments.
pub const PAYMENT_REQUIRED_NO_GATEWAY: &str = "payment required for this model, but this node has no payment gateway configured to collect it; sign in as a caller this node's access policy names";

pub async fn payment_gate_handler(
    State(middleware): State<PaymentGateMiddleware>,
    mut request: Request,
    next: Next,
) -> Result<Response, PaymentGateError> {
    let uri = request.uri().clone();
    let resource = uri.path();

    debug!("Payment gate checking resource: {}", resource);

    // Every inference route runs the node's one admission check before any
    // payment logic: a key admits, a gated or private model is refused without
    // a pay-per-call challenge, and a public model falls through to the x402
    // challenge below (or is admitted outright when its price is zero).
    if let Some(ref auth) = middleware.inference_admission
        && INFERENCE_ROUTES.contains(&request.uri().path())
    {
        let (classified, decision) = classify(auth.as_ref(), request).await?;
        match decision {
            InferenceAccess::Allow => return Ok(next.run(classified).await),
            InferenceAccess::Refuse(status, msg) => return Ok(refusal_response(status, &msg)),
            InferenceAccess::NeedPayment => request = classified,
        }
    }

    let credential =
        credential_from_headers(|name| request.headers().get(name).and_then(|v| v.to_str().ok()));

    if let Some(credential) = credential {
        let credential = credential.map_err(|e| {
            warn!("Failed to parse payment credential: {}", e);
            PaymentGateError::InvalidCredential(e.to_string())
        })?;
        debug!(
            "Verifying credential {} for challenge {}",
            credential.credential_id, credential.challenge_id
        );

        // The credential must pay for this resource, to this gate's payee, at
        // this gate's price. Payer identity (delegation scope, spending
        // policy, lifecycle) is checked by the gateway.
        let expect = crate::gateway::PaymentExpectation::Resource {
            resource,
            payee: &middleware.config.recipient,
            min_amount: middleware.config.default_amount,
            asset: &middleware.config.default_asset,
        };
        // A metered credential is checked now and settled once the work's
        // cost is known. Handlers report that cost in TNZO wei, so only a
        // TNZO charge can be metered; any other asset settles as declared.
        if middleware.metered_settlement
            && credential.asset.eq_ignore_ascii_case("TNZO")
            && (credential
                .extra
                .contains_key(crate::payer_auth::UPTO_MAX_KEY)
                || credential
                    .extra
                    .contains_key(crate::payer_auth::CUMULATIVE_AMOUNT_KEY))
        {
            let challenge = middleware
                .gateway
                .verify_metered(&credential, expect)
                .await
                .map_err(|e| PaymentGateError::VerificationFailed(e.to_string()))?;
            let settle = MeteredSettle {
                gateway: middleware.gateway.clone(),
                meter: middleware.meter.clone(),
                challenge,
                credential,
                config: middleware.config.clone(),
                resource: resource.to_string(),
            };
            return serve_then_settle_metered(settle, &middleware.in_flight, request, next).await;
        }
        match middleware
            .gateway
            .verify_and_settle(&credential, expect)
            .await
        {
            Ok(receipt) => {
                debug!(
                    "Payment verified and settled: receipt_id={}, amount={}",
                    receipt.receipt_id, receipt.amount
                );
                let mut response = next.run(request).await;
                if let Some(value) = payment_response_header(&receipt) {
                    response
                        .headers_mut()
                        .insert(crate::x402::PAYMENT_RESPONSE_HEADER, value);
                }
                if let Some(value) = payment_receipt_header(&receipt) {
                    response
                        .headers_mut()
                        .insert(crate::mpp::PAYMENT_RECEIPT_HEADER, value);
                }
                Ok(response)
            }
            Err(e) => {
                warn!("Payment verification failed: {}", e);
                Err(PaymentGateError::VerificationFailed(e.to_string()))
            }
        }
    } else {
        // No credential — return HTTP 402 with challenge
        debug!("No payment credential found, issuing challenge");

        let challenge = middleware
            .gateway
            .create_challenge(
                &middleware.config.default_protocol,
                resource,
                middleware.config.default_amount,
                &middleware.config.default_asset,
                &middleware.config.recipient,
            )
            .await
            .map_err(|e| PaymentGateError::ChallengeCreationFailed(e.to_string()))?;

        debug!(
            "Created challenge {} for resource {} (amount={} {})",
            challenge.challenge_id, resource, challenge.amount, challenge.asset
        );

        Err(PaymentGateError::PaymentRequired(challenge))
    }
}

/// What a metered request is settled against, owned so a stream can settle
/// after the handler returned.
struct MeteredSettle {
    gateway: Arc<dyn PaymentGateway>,
    meter: Option<Arc<dyn UsageMeter>>,
    challenge: crate::types::PaymentChallenge,
    credential: PaymentCredential,
    config: PaymentGateConfig,
    resource: String,
}

impl MeteredSettle {
    /// Settle at `metered` (the cost the handler reported), capped at the
    /// payer's signed ceiling, or at the charge the credential declared when
    /// the handler reported none. A challenge that names a meter key is
    /// charged only with a usage record that meter signed.
    async fn settle(
        mut self,
        metered: Option<u128>,
    ) -> crate::Result<crate::types::PaymentReceipt> {
        let ceiling = crate::payer_auth::authorized_ceiling(&self.credential)?;
        let charge = metered.map_or(self.credential.amount, |m| m.min(ceiling));
        // A voucher pays the metered charge on the payer's channel; the usage
        // record belongs to the signed `upto` ceiling.
        let upto = self
            .credential
            .extra
            .contains_key(crate::payer_auth::UPTO_MAX_KEY);
        let record = if upto
            && self
                .challenge
                .extra
                .contains_key(crate::metering::METER_KEY)
        {
            let meter = self.meter.as_ref().ok_or_else(|| {
                crate::PaymentError::ConfigError(
                    "this challenge is metered but the gate has no meter".to_string(),
                )
            })?;
            let lines = vec![crate::metering::UsageLine {
                unit: METERED_UNIT.to_string(),
                quantity: 1,
                unit_price: charge,
            }];
            Some(meter.meter(&self.challenge, &mut self.credential, lines)?)
        } else {
            self.credential.amount = charge;
            None
        };
        let expect = crate::gateway::PaymentExpectation::Resource {
            resource: &self.resource,
            payee: &self.config.recipient,
            min_amount: self.config.default_amount,
            asset: &self.config.default_asset,
        };
        let mut receipt = self
            .gateway
            .verify_and_settle(&self.credential, expect)
            .await?;
        if let Some(record) = record {
            receipt.extra.insert(
                crate::metering::USAGE_RECORD_KEY.to_string(),
                serde_json::to_value(&record)
                    .map_err(|e| crate::PaymentError::SerializationError(e.to_string()))?,
            );
        }
        Ok(receipt)
    }
}

/// Releases a challenge's in-flight claim when dropped.
struct InFlightRelease(Arc<dashmap::DashSet<String>>, String);

impl Drop for InFlightRelease {
    fn drop(&mut self) {
        self.0.remove(&self.1);
    }
}

/// The last `"cost_wei":"<digits>"` in `text`.
fn last_cost_in(text: &[u8]) -> Option<u128> {
    const NEEDLE: &[u8] = b"\"cost_wei\":\"";
    let start = text.windows(NEEDLE.len()).rposition(|w| w == NEEDLE)? + NEEDLE.len();
    let digits: Vec<u8> = text[start..]
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .copied()
        .collect();
    if text.get(start + digits.len()) != Some(&b'"') {
        return None;
    }
    std::str::from_utf8(&digits).ok()?.parse().ok()
}

/// Passes an SSE body through unchanged while remembering the last cost it
/// reports, and settles once the body ends, or is dropped because the client
/// went away, at that cost, or as declared when none was seen.
struct MeteredStream {
    inner: axum::body::BodyDataStream,
    /// Tail of the previous chunk, so a cost split across chunks is found.
    tail: Vec<u8>,
    last_cost: Option<u128>,
    settle: Option<(MeteredSettle, InFlightRelease)>,
}

const TAIL_KEEP: usize = 128;

impl futures::Stream for MeteredStream {
    type Item = Result<bytes::Bytes, axum::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let polled = std::pin::Pin::new(&mut self.inner).poll_next(cx);
        if let std::task::Poll::Ready(Some(Ok(chunk))) = &polled {
            let mut window = std::mem::take(&mut self.tail);
            window.extend_from_slice(chunk);
            if let Some(c) = last_cost_in(&window) {
                self.last_cost = Some(c);
            }
            let keep = window.len().saturating_sub(TAIL_KEEP);
            self.tail = window.split_off(keep);
        }
        polled
    }
}

impl Drop for MeteredStream {
    fn drop(&mut self) {
        let Some((settle, release)) = self.settle.take() else {
            return;
        };
        let metered = self.last_cost;
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            warn!(
                challenge = %settle.challenge.challenge_id,
                "no runtime to settle a metered stream on; left unsettled"
            );
            return;
        };
        handle.spawn(async move {
            let challenge_id = settle.challenge.challenge_id.clone();
            match settle.settle(metered).await {
                Ok(r) => debug!(
                    "Metered stream settled: receipt_id={}, amount={}",
                    r.receipt_id, r.amount
                ),
                Err(e) => warn!(
                    challenge = %challenge_id,
                    error = %e,
                    "Metered stream settlement failed after serving"
                ),
            }
            drop(release);
        });
    }
}

/// Serve a checked `upto` request, then settle what it actually cost.
///
/// - A non-success response is not charged; the credential stays usable
///   until its challenge expires.
/// - A JSON response carrying [`METERED_COST_FIELD`] settles at that cost,
///   capped at the payer's signed ceiling, before it is returned.
/// - A server-sent-event stream passes through unchanged and settles when it
///   ends, at the last cost it reported.
/// - Anything without a reported cost settles at the charge the credential
///   declared.
async fn serve_then_settle_metered(
    settle: MeteredSettle,
    in_flight: &Arc<dashmap::DashSet<String>>,
    request: Request,
    next: Next,
) -> Result<Response, PaymentGateError> {
    let id = settle.challenge.challenge_id.clone();
    if !in_flight.insert(id.clone()) {
        return Err(PaymentGateError::VerificationFailed(
            "this payment credential is already paying for a request in progress".to_string(),
        ));
    }
    let release = InFlightRelease(in_flight.clone(), id);

    let response = next.run(request).await;
    if !response.status().is_success() {
        return Ok(response);
    }

    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    if content_type.starts_with("text/event-stream") {
        let (parts, body) = response.into_parts();
        let stream = MeteredStream {
            inner: body.into_data_stream(),
            tail: Vec::new(),
            last_cost: None,
            settle: Some((settle, release)),
        };
        return Ok(Response::from_parts(parts, Body::from_stream(stream)));
    }
    let _release = release;

    let (response, metered) = if content_type.starts_with("application/json") {
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, METERED_BODY_LIMIT)
            .await
            .map_err(|e| PaymentGateError::VerificationFailed(format!("response read: {e}")))?;
        let cost = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| {
                v.get(METERED_COST_FIELD)
                    .and_then(|c| c.as_str())
                    .and_then(|c| c.parse::<u128>().ok())
            });
        (Response::from_parts(parts, Body::from(bytes)), cost)
    } else {
        (response, None)
    };

    let challenge_id = settle.challenge.challenge_id.clone();
    match settle.settle(metered).await {
        Ok(receipt) => {
            debug!(
                "Metered settlement: receipt_id={}, amount={}",
                receipt.receipt_id, receipt.amount
            );
            let mut response = response;
            if let Some(value) = payment_response_header(&receipt) {
                response
                    .headers_mut()
                    .insert(crate::x402::PAYMENT_RESPONSE_HEADER, value);
            }
            if let Some(value) = payment_receipt_header(&receipt) {
                response
                    .headers_mut()
                    .insert(crate::mpp::PAYMENT_RECEIPT_HEADER, value);
            }
            Ok(response)
        }
        Err(e) => {
            // The work is done and was authorized; the settlement failing is
            // the operator's to chase, not a reason to withhold the result.
            warn!(
                challenge = %challenge_id,
                error = %e,
                "Metered settlement failed after serving"
            );
            Ok(response)
        }
    }
}

/// Escapes backslashes and double-quotes for inclusion inside an RFC 7230 quoted-string.
/// Used when building the `WWW-Authenticate: Payment ...` header per
/// `draft-ryan-httpauth-payment-01` ABNF: `auth-param = token BWS "=" BWS ( token / quoted-string )`.
fn escape_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' | '"' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// The payment a request carries, if any:
///
/// - `PAYMENT-SIGNATURE: <base64 JSON>`, an x402 payment payload;
/// - `Authorization: Payment <base64url JSON>`, a credential in the HTTP
///   Payment authentication scheme;
/// - `Payment-Credential: <base64 JSON>`, a credential.
///
/// `header` looks a header up by name.
pub fn credential_from_headers<'a>(
    header: impl Fn(&str) -> Option<&'a str>,
) -> Option<crate::error::Result<PaymentCredential>> {
    if let Some(value) = header(crate::x402::PAYMENT_SIGNATURE_HEADER) {
        return Some(crate::x402::credential_from_header(value));
    }
    if let Some(value) = header("Authorization").and_then(|v| v.strip_prefix("Payment ")) {
        return Some(
            crate::mpp::IetfPaymentBody::from_base64url(value)
                .and_then(crate::mpp::IetfPaymentBody::into_credential),
        );
    }
    header("Payment-Credential").map(decode_credential)
}

fn decode_credential(data: &str) -> crate::error::Result<PaymentCredential> {
    use base64::{Engine as _, engine::general_purpose};
    let json = general_purpose::STANDARD.decode(data.trim()).map_err(|e| {
        crate::error::PaymentError::CredentialError(format!("credential is not base64: {e}"))
    })?;
    Ok(serde_json::from_slice(&json)?)
}

/// The `Payment-Receipt` header for an MPP receipt.
pub fn payment_receipt_header(
    receipt: &crate::types::PaymentReceipt,
) -> Option<axum::http::HeaderValue> {
    if !receipt.protocol.eq_ignore_ascii_case("mpp") {
        return None;
    }
    let body = crate::mpp::MppReceipt::from_receipt(receipt)?
        .to_header()
        .ok()?;
    axum::http::HeaderValue::from_str(&body).ok()
}

/// The `PAYMENT-RESPONSE` header for an x402 receipt.
pub fn payment_response_header(
    receipt: &crate::types::PaymentReceipt,
) -> Option<axum::http::HeaderValue> {
    if !receipt.protocol.eq_ignore_ascii_case("x402") {
        return None;
    }
    let body = crate::x402::X402SettlementResponse::from_receipt(receipt)?;
    axum::http::HeaderValue::from_str(&body.to_base64().ok()?).ok()
}

/// The `PAYMENT-REQUIRED` header for an x402 challenge.
pub fn payment_required_header(
    challenge: &crate::types::PaymentChallenge,
) -> Option<axum::http::HeaderValue> {
    if !challenge.protocol.eq_ignore_ascii_case("x402") {
        return None;
    }
    let body = crate::x402::payment_required_for(challenge)
        .to_base64()
        .ok()?;
    axum::http::HeaderValue::from_str(&body).ok()
}

/// Header a reverse proxy sets to the method of the request it forwards.
pub const FORWARDED_METHOD_HEADER: &str = "x-forwarded-method";
/// Header a reverse proxy sets to the path and query of the request it forwards.
pub const FORWARDED_URI_HEADER: &str = "x-forwarded-uri";

/// Decide for a reverse proxy whether the request it forwards is paid. The
/// proxy sends the original method and URI (`X-Forwarded-Method`,
/// `X-Forwarded-Uri`) with the original headers and no body, and serves the
/// request only on a 2xx; anything else it returns to the client as is, so
/// an unpaid request gets the 402 with its challenge and never reaches the
/// site. The gate runs exactly as on the node's own paid routes: a payment
/// is settled before the answer is 2xx.
pub async fn forward_auth(middleware: PaymentGateMiddleware, request: Request) -> Response {
    let headers = request.headers().clone();
    let uri = headers
        .get(FORWARDED_URI_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|u| u.starts_with('/'))
        .unwrap_or("/")
        .to_string();
    let method = headers
        .get(FORWARDED_METHOD_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|m| axum::http::Method::from_bytes(m.as_bytes()).ok())
        .unwrap_or(axum::http::Method::GET);
    let Ok(mut forwarded) = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    *forwarded.headers_mut() = headers;
    let decide = axum::Router::new()
        .fallback(|| async { StatusCode::OK })
        .layer(axum::middleware::from_fn_with_state(
            middleware,
            payment_gate_handler,
        ));
    match tower::ServiceExt::oneshot(decide, forwarded).await {
        Ok(response) => response,
        Err(never) => match never {},
    }
}

/// Errors that can occur during payment gate processing
#[derive(Debug)]
pub enum PaymentGateError {
    /// No payment credential provided — return HTTP 402
    PaymentRequired(crate::types::PaymentChallenge),
    /// Credential parsing failed
    InvalidCredential(String),
    /// Challenge creation failed
    ChallengeCreationFailed(String),
    /// Credential verification failed
    VerificationFailed(String),
    /// The request body is larger than its route accepts (the ceiling in
    /// bytes), or could not be read whole.
    PayloadTooLarge(usize),
}

/// The HTTP Payment `method` a challenge of `protocol` names: MPP payments on
/// Tenzro use the `tenzro` method (docs/standards/mpp-method-tenzro.md);
/// other protocols name themselves.
pub fn payment_method(protocol: &str) -> &str {
    if protocol.eq_ignore_ascii_case("mpp") {
        "tenzro"
    } else {
        protocol
    }
}

impl IntoResponse for PaymentGateError {
    fn into_response(self) -> Response {
        match self {
            PaymentGateError::PaymentRequired(challenge) => {
                let body = serde_json::to_string(&challenge).unwrap_or_else(|_| "{}".to_string());

                // Build IETF-compliant WWW-Authenticate per draft-ryan-httpauth-payment-01.
                // ABNF: challenge = "Payment" 1*SP auth-params
                // Required params: id, realm, method, intent, request
                // Optional: expires, digest, description, opaque
                let request_b64 = {
                    use base64::{Engine as _, engine::general_purpose};
                    // Embed the JSON challenge body as base64url-nopad-encoded request param
                    general_purpose::URL_SAFE_NO_PAD.encode(body.as_bytes())
                };
                let www_auth = format!(
                    "Payment id=\"{}\", realm=\"{}\", method=\"{}\", intent=\"charge\", \
                     request=\"{}\", expires=\"{}\"",
                    escape_quoted(&challenge.challenge_id),
                    escape_quoted(&challenge.resource),
                    escape_quoted(payment_method(&challenge.protocol)),
                    request_b64,
                    challenge.expires_at.to_rfc3339(),
                );

                let mut builder = Response::builder()
                    .status(StatusCode::PAYMENT_REQUIRED)
                    .header(header::WWW_AUTHENTICATE, www_auth)
                    .header(header::CONTENT_TYPE, "application/json");
                if let Some(required) = payment_required_header(&challenge) {
                    builder = builder.header(crate::x402::PAYMENT_REQUIRED_HEADER, required);
                }
                builder.body(Body::from(body)).unwrap()
            }
            PaymentGateError::InvalidCredential(msg) => Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(format!(
                    "{{\"error\":\"invalid_credential\",\"message\":\"{}\"}}",
                    msg
                )))
                .unwrap(),
            PaymentGateError::ChallengeCreationFailed(msg) => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(format!(
                    "{{\"error\":\"challenge_creation_failed\",\"message\":\"{}\"}}",
                    msg
                )))
                .unwrap(),
            PaymentGateError::VerificationFailed(msg) => Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from(format!(
                    "{{\"error\":\"verification_failed\",\"message\":\"{}\"}}",
                    msg
                )))
                .unwrap(),
            PaymentGateError::PayloadTooLarge(limit) => Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(Body::from(format!(
                    "{{\"error\":\"payload_too_large\",\"message\":\"the request body exceeds this route's {limit} bytes, or ended early\"}}"
                )))
                .unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::{RailOutcome, TenzroPaymentGateway};
    use crate::test_support::{RecordingRail, TestProtocol, signer};
    use crate::traits::PaymentProtocol;
    use axum::{Router, routing::get};
    use std::collections::HashMap;
    use tower::ServiceExt;

    const PAYEE: &str = "0909090909090909090909090909090909090909";

    async fn test_handler() -> &'static str {
        "success"
    }

    fn gate_config() -> PaymentGateConfig {
        PaymentGateConfig {
            default_amount: 1000,
            default_asset: "TNZO".to_string(),
            recipient: PAYEE.to_string(),
            default_protocol: "test".to_string(),
        }
    }

    fn gated_app(gateway: Arc<TenzroPaymentGateway>) -> Router {
        let store = gateway.challenge_store();
        let middleware = PaymentGateMiddleware::new(gateway, gate_config(), store);
        Router::new()
            .route("/paid-resource", get(test_handler))
            .route("/other-resource", get(test_handler))
            .layer(axum::middleware::from_fn_with_state(
                middleware,
                payment_gate_handler,
            ))
    }

    fn gateway_with(rail: Arc<RecordingRail>) -> Arc<TenzroPaymentGateway> {
        let gw =
            TenzroPaymentGateway::new(1337, std::sync::Arc::new(crate::test_support::SeedKeys))
                .with_rail(rail);
        gw.register_protocol(Arc::new(TestProtocol));
        Arc::new(gw)
    }

    fn encode(credential: &PaymentCredential) -> String {
        use base64::{Engine as _, engine::general_purpose};
        general_purpose::STANDARD.encode(serde_json::to_string(credential).unwrap())
    }

    #[tokio::test]
    async fn forward_auth_answers_402_unpaid_and_2xx_only_once_paid() {
        let rail = RecordingRail::new(RailOutcome::Settled {
            reference: "0xtx".to_string(),
        });
        let gateway = gateway_with(rail.clone());
        let store = gateway.challenge_store();
        let middleware = PaymentGateMiddleware::new(gateway.clone(), gate_config(), store);
        let ask = |credential: Option<String>| {
            let mut b = Request::builder()
                .uri("/forward-auth")
                .header(FORWARDED_METHOD_HEADER, "GET")
                .header(FORWARDED_URI_HEADER, "/articles/1");
            if let Some(c) = credential {
                b = b.header("Payment-Credential", c);
            }
            forward_auth(middleware.clone(), b.body(Body::empty()).unwrap())
        };
        let unpaid = ask(None).await;
        assert_eq!(unpaid.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(rail.calls.load(std::sync::atomic::Ordering::SeqCst), 0);

        let challenge = gateway
            .create_challenge("test", "/articles/1", 1000, "TNZO", PAYEE)
            .await
            .unwrap();
        let credential = TestProtocol
            .create_credential(&challenge, "", &signer())
            .await
            .unwrap();
        let paid = ask(Some(encode(&credential))).await;
        assert_eq!(paid.status(), StatusCode::OK);
        assert_eq!(rail.calls.load(std::sync::atomic::Ordering::SeqCst), 1);

        // A payment for another path does not open this one.
        let other = gateway
            .create_challenge("test", "/elsewhere", 1000, "TNZO", PAYEE)
            .await
            .unwrap();
        let elsewhere = TestProtocol
            .create_credential(&other, "", &signer())
            .await
            .unwrap();
        assert_ne!(ask(Some(encode(&elsewhere))).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_middleware_returns_402_without_credential() {
        let rail = RecordingRail::new(RailOutcome::Settled {
            reference: "0xtx".to_string(),
        });
        let app = gated_app(gateway_with(rail));
        let request = Request::builder()
            .uri("/paid-resource")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let www_auth = response
            .headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .expect("WWW-Authenticate header must be set on 402 response")
            .to_str()
            .unwrap();
        assert!(www_auth.starts_with("Payment "), "got: {www_auth}");
        assert!(www_auth.contains("realm="));
        assert!(www_auth.contains("method=\"test\""));
    }

    /// An MPP challenge names the `tenzro` payment method, as the method
    /// document specifies; the protocol stays `mpp` in the challenge body.
    #[test]
    fn an_mpp_challenge_names_the_tenzro_payment_method() {
        let challenge = crate::types::PaymentChallenge {
            challenge_id: "ch_1".into(),
            protocol: "mpp".into(),
            resource: "/paid".into(),
            amount: 10,
            asset: "TNZO".into(),
            recipient: "0909090909090909090909090909090909090909".into(),
            chain: "tenzro".into(),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(60),
            extra: Default::default(),
        };
        let response = PaymentGateError::PaymentRequired(challenge).into_response();
        let www_auth = response
            .headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(www_auth.contains("method=\"tenzro\""), "{www_auth}");
        assert!(!www_auth.contains("method=\"mpp\""), "{www_auth}");
    }

    #[tokio::test]
    async fn a_credential_for_this_resource_is_served_after_settlement() {
        let rail = RecordingRail::new(RailOutcome::Settled {
            reference: "0xtx".to_string(),
        });
        let gateway = gateway_with(rail.clone());
        let challenge = gateway
            .create_challenge("test", "/paid-resource", 1000, "TNZO", PAYEE)
            .await
            .unwrap();
        let credential = TestProtocol
            .create_credential(&challenge, "", &signer())
            .await
            .unwrap();
        let app = gated_app(gateway);
        let request = Request::builder()
            .uri("/paid-resource")
            .header("Payment-Credential", encode(&credential))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            rail.calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "served only after the rail settled"
        );
    }

    #[tokio::test]
    async fn a_credential_for_a_self_minted_cheap_challenge_is_refused() {
        let rail = RecordingRail::new(RailOutcome::Settled {
            reference: "0xtx".to_string(),
        });
        let gateway = gateway_with(rail.clone());
        // One unit, paid to the attacker's own address.
        let cheap = gateway
            .create_challenge(
                "test",
                "/paid-resource",
                1,
                "TNZO",
                "0707070707070707070707070707070707070707",
            )
            .await
            .unwrap();
        let credential = TestProtocol
            .create_credential(&cheap, "", &signer())
            .await
            .unwrap();
        let app = gated_app(gateway);
        let request = Request::builder()
            .uri("/paid-resource")
            .header("Payment-Credential", encode(&credential))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_ne!(response.status(), StatusCode::OK);
        assert_eq!(rail.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_credential_for_another_resource_is_refused() {
        let rail = RecordingRail::new(RailOutcome::Settled {
            reference: "0xtx".to_string(),
        });
        let gateway = gateway_with(rail.clone());
        let challenge = gateway
            .create_challenge("test", "/other-resource", 1000, "TNZO", PAYEE)
            .await
            .unwrap();
        let credential = TestProtocol
            .create_credential(&challenge, "", &signer())
            .await
            .unwrap();
        let app = gated_app(gateway);
        let request = Request::builder()
            .uri("/paid-resource")
            .header("Payment-Credential", encode(&credential))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_ne!(response.status(), StatusCode::OK);
        assert_eq!(rail.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    fn bare_credential() -> PaymentCredential {
        PaymentCredential {
            credential_id: "cred-1".to_string(),
            challenge_id: "ch-1".to_string(),
            protocol: "x402".to_string(),
            payer_did: String::new(),
            payer_address: "ab".repeat(20),
            amount: 1000,
            asset: "TNZO".to_string(),
            signature: None,
            extra: HashMap::new(),
        }
    }

    #[test]
    fn a_credential_is_read_from_each_carrier() {
        use base64::{Engine as _, engine::general_purpose};
        let credential = bare_credential();
        let json = serde_json::to_string(&credential).unwrap();

        let raw = general_purpose::STANDARD.encode(&json);
        let got = credential_from_headers(|n| (n == "Payment-Credential").then_some(raw.as_str()))
            .unwrap()
            .unwrap();
        assert_eq!(got.credential_id, "cred-1");

        let auth = crate::mpp::IetfPaymentBody::for_credential(&credential)
            .unwrap()
            .to_header()
            .unwrap();
        let got = credential_from_headers(|n| (n == "Authorization").then_some(auth.as_str()))
            .unwrap()
            .unwrap();
        assert_eq!(got.credential_id, "cred-1");

        let mut challenge = crate::types::PaymentChallenge {
            challenge_id: "ch-1".to_string(),
            protocol: "x402".to_string(),
            resource: "/paid-resource".to_string(),
            amount: 1000,
            asset: "TNZO".to_string(),
            recipient: PAYEE.to_string(),
            chain: "tenzro".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(1),
            extra: HashMap::new(),
        };
        challenge
            .extra
            .insert("network".to_string(), serde_json::json!("tenzro:1337"));
        let signature = crate::x402::wire::payload_for_credential(&challenge, &credential)
            .unwrap()
            .to_base64()
            .unwrap();
        let got = credential_from_headers(|n| {
            (n == crate::x402::PAYMENT_SIGNATURE_HEADER).then_some(signature.as_str())
        })
        .unwrap()
        .unwrap();
        assert_eq!(got.challenge_id, "ch-1");

        assert!(credential_from_headers(|_| None).is_none());
        let bogus = "Bearer abc";
        assert!(credential_from_headers(|n| (n == "Authorization").then_some(bogus)).is_none());
    }

    /// An `InferenceAdmission` double: decides the same way regardless of
    /// which model or headers it's asked about, so a test can assert what
    /// the middleware does with a given decision without a real access
    /// policy or served-model registry behind it.
    struct FixedAdmission(InferenceAccess);

    impl InferenceAdmission for FixedAdmission {
        fn decide(
            &self,
            _headers: &axum::http::HeaderMap,
            _model_id: Option<&str>,
        ) -> InferenceAccess {
            self.0.clone()
        }
    }

    /// Regression test for the actual production bug: `/tenzro/forecasts`
    /// was added to `PAID_ROUTES` and given a handler, but never added to
    /// this match arm, so an admitted caller that skipped payment on
    /// `/v1/chat/completions` fell straight through to an x402 challenge
    /// here -- an `Allow` decision was reachable but never consulted for
    /// this path. If the match arm regresses, this goes back to failing
    /// exactly the way the live bug did.
    #[tokio::test]
    async fn test_forecasts_route_is_covered_by_inference_admission() {
        let gateway = gateway_with(RecordingRail::new(RailOutcome::Settled {
            reference: "0xtx".to_string(),
        }));
        let challenge_store = gateway.challenge_store();
        let middleware = PaymentGateMiddleware::new(gateway, gate_config(), challenge_store)
            .with_inference_admission(Arc::new(FixedAdmission(InferenceAccess::Allow)));

        let app = Router::new()
            .route("/tenzro/forecasts", axum::routing::post(test_handler))
            .layer(axum::middleware::from_fn_with_state(
                middleware,
                payment_gate_handler,
            ));

        let request = Request::builder()
            .method("POST")
            .uri("/tenzro/forecasts")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"model":"chronos-2","history":[1,2,3],"horizon":1}"#,
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // An Allow decision must skip payment entirely -- no credential was
        // presented, so a 402 here would mean the pre-check either doesn't
        // run for this path or ignores what it decided.
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// The other half: without an `InferenceAdmission` wired at all (the
    /// state most nodes run in absent explicit configuration), the route
    /// still falls back to the ordinary x402 challenge. The fix widens who
    /// can skip payment; it does not make the route free.
    #[tokio::test]
    async fn test_forecasts_route_still_needs_payment_without_admission() {
        let gateway = gateway_with(RecordingRail::new(RailOutcome::Settled {
            reference: "0xtx".to_string(),
        }));
        let challenge_store = gateway.challenge_store();
        let middleware = PaymentGateMiddleware::new(gateway, gate_config(), challenge_store);

        let app = Router::new()
            .route("/tenzro/forecasts", axum::routing::post(test_handler))
            .layer(axum::middleware::from_fn_with_state(
                middleware,
                payment_gate_handler,
            ));

        let request = Request::builder()
            .method("POST")
            .uri("/tenzro/forecasts")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"model":"chronos-2","history":[1,2,3],"horizon":1}"#,
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    }

    /// A gate on `/v1/chat/completions` whose handler answers `status` with
    /// `body`, and an `upto` credential with a declared charge of 800 under a
    /// signed ceiling of 900, against a 1000 challenge.
    struct Metered {
        app: Router,
        rail: Arc<RecordingRail>,
        middleware: PaymentGateMiddleware,
        challenge: crate::types::PaymentChallenge,
        credential: String,
    }

    async fn metered_app(
        metered_on: bool,
        meter_key: bool,
        meter: Option<Arc<dyn UsageMeter>>,
        handler: axum::routing::MethodRouter,
    ) -> Metered {
        let rail = RecordingRail::new(RailOutcome::Settled {
            reference: "0xtx".to_string(),
        });
        let gateway = gateway_with(rail.clone());
        let mut challenge = gateway
            .create_challenge("test", "/v1/chat/completions", 1000, "TNZO", PAYEE)
            .await
            .unwrap();
        if meter_key {
            challenge.extra.insert(
                crate::metering::METER_KEY.to_string(),
                serde_json::json!("ab"),
            );
            gateway.challenge_store().store(&challenge).unwrap();
        }
        let credential =
            crate::payer_auth::sign_credential(&challenge, "test", "", &signer(), 800, 900)
                .unwrap();
        let store = gateway.challenge_store();
        let mut middleware = PaymentGateMiddleware::new(gateway, gate_config(), store)
            .with_metered_settlement(metered_on);
        if let Some(meter) = meter {
            middleware = middleware.with_meter(meter);
        }
        let app = Router::new().route("/v1/chat/completions", handler).layer(
            axum::middleware::from_fn_with_state(middleware.clone(), payment_gate_handler),
        );
        Metered {
            app,
            rail,
            middleware,
            challenge,
            credential: encode(&credential),
        }
    }

    fn cost_handler(status: StatusCode, cost: &'static str) -> axum::routing::MethodRouter {
        get(move || async move {
            (
                status,
                axum::Json(serde_json::json!({ "cost_wei": cost, "choices": [] })),
            )
        })
    }

    fn paid_request(credential: &str) -> Request {
        Request::builder()
            .uri("/v1/chat/completions")
            .header("Payment-Credential", credential)
            .body(Body::empty())
            .unwrap()
    }

    fn charged(rail: &RecordingRail) -> Vec<u128> {
        rail.seen.lock().unwrap().iter().map(|i| i.amount).collect()
    }

    #[tokio::test]
    async fn metered_settlement_charges_the_reported_cost() {
        let m = metered_app(true, false, None, cost_handler(StatusCode::OK, "300")).await;
        let resp = m.app.oneshot(paid_request(&m.credential)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(charged(&m.rail), vec![300]);
        // The body still reaches the caller intact.
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["cost_wei"], "300");
    }

    #[tokio::test]
    async fn a_metered_charge_is_capped_at_the_signed_ceiling() {
        let m = metered_app(true, false, None, cost_handler(StatusCode::OK, "5000")).await;
        let resp = m.app.oneshot(paid_request(&m.credential)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(charged(&m.rail), vec![900]);
    }

    #[tokio::test]
    async fn a_failed_response_is_not_charged() {
        let m = metered_app(
            true,
            false,
            None,
            cost_handler(StatusCode::INTERNAL_SERVER_ERROR, "300"),
        )
        .await;
        let resp = m.app.oneshot(paid_request(&m.credential)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(charged(&m.rail).is_empty());
    }

    #[tokio::test]
    async fn without_metered_settlement_the_declared_charge_settles_first() {
        let m = metered_app(false, false, None, cost_handler(StatusCode::OK, "300")).await;
        let resp = m.app.oneshot(paid_request(&m.credential)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(charged(&m.rail), vec![800]);
    }

    /// One `upto` credential serves one request at a time: a second request
    /// on a credential already in flight is refused and nothing is charged.
    #[tokio::test]
    async fn a_credential_already_in_flight_is_refused() {
        let m = metered_app(true, false, None, cost_handler(StatusCode::OK, "300")).await;
        m.middleware
            .in_flight
            .insert(m.challenge.challenge_id.clone());
        let resp = m.app.oneshot(paid_request(&m.credential)).await.unwrap();
        assert_ne!(resp.status(), StatusCode::OK);
        assert!(charged(&m.rail).is_empty());
    }

    /// Records the lines it was asked to meter and charges their total.
    struct FakeMeter(std::sync::Mutex<Vec<crate::metering::UsageLine>>);

    impl UsageMeter for FakeMeter {
        fn meter(
            &self,
            challenge: &crate::types::PaymentChallenge,
            credential: &mut PaymentCredential,
            lines: Vec<crate::metering::UsageLine>,
        ) -> crate::Result<crate::metering::UsageRecord> {
            let charge: u128 = lines.iter().map(|l| l.unit_price * l.quantity).sum();
            credential.amount = charge;
            self.0.lock().unwrap().extend(lines.clone());
            Ok(crate::metering::UsageRecord {
                challenge_id: challenge.challenge_id.clone(),
                payer: String::new(),
                ceiling: 900,
                lines,
                measured_at_ms: 0,
                commitments: Default::default(),
                meter_key: "ab".to_string(),
                signature: tenzro_crypto::CompositeSignature::classical(
                    tenzro_crypto::ClassicalProof::Raw {
                        signature: Vec::new(),
                    },
                ),
            })
        }
    }

    /// A challenge that names a meter key is charged only through the meter:
    /// with one, the record covers exactly the reported cost; without one,
    /// nothing settles.
    #[tokio::test]
    async fn a_metered_challenge_is_charged_through_the_meter() {
        let meter = Arc::new(FakeMeter(std::sync::Mutex::new(Vec::new())));
        let m = metered_app(
            true,
            true,
            Some(meter.clone()),
            cost_handler(StatusCode::OK, "300"),
        )
        .await;
        let resp = m.app.oneshot(paid_request(&m.credential)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(charged(&m.rail), vec![300]);
        let lines = meter.0.lock().unwrap().clone();
        assert_eq!(lines.len(), 1);
        assert_eq!((lines[0].quantity, lines[0].unit_price), (1, 300));

        let unmetered = metered_app(true, true, None, cost_handler(StatusCode::OK, "300")).await;
        let resp = unmetered
            .app
            .oneshot(paid_request(&unmetered.credential))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(charged(&unmetered.rail).is_empty());
    }

    #[test]
    fn finds_the_last_reported_cost() {
        assert_eq!(
            last_cost_in(br#"data: {"cost_wei":"12"}\n\ndata: {"cost_wei":"30"}"#),
            Some(30)
        );
        assert_eq!(
            last_cost_in(br#"data: {"cost_wei":"3"#),
            None,
            "truncated value"
        );
        assert_eq!(last_cost_in(br#"data: {"cost_wei":"x1"}"#), None);
        assert_eq!(last_cost_in(b"data: {}"), None);
    }

    #[tokio::test]
    async fn a_metered_stream_settles_its_reported_cost_when_it_ends() {
        let handler = get(|| async {
            // The cost arrives split across two chunks.
            let chunks: Vec<Result<bytes::Bytes, std::io::Error>> = vec![
                Ok(bytes::Bytes::from_static(
                    b"data: {\"choices\":[]}\n\ndata: {\"cost_w",
                )),
                Ok(bytes::Bytes::from_static(
                    b"ei\":\"400\"}\n\ndata: [DONE]\n\n",
                )),
            ];
            Response::builder()
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(Body::from_stream(futures::stream::iter(chunks)))
                .unwrap()
        });
        let m = metered_app(true, false, None, handler).await;
        let resp = m.app.oneshot(paid_request(&m.credential)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // Nothing is settled until the stream has been consumed.
        assert!(charged(&m.rail).is_empty());
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        assert!(
            body.ends_with(b"data: [DONE]\n\n"),
            "stream passes through unchanged"
        );
        for _ in 0..100 {
            if !charged(&m.rail).is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(charged(&m.rail), vec![400]);
    }

    /// The voucher rail a node's payment sessions give the gateway, recording
    /// every charge it accepts.
    struct Channel(std::sync::Mutex<Vec<u128>>);

    #[async_trait::async_trait]
    impl crate::gateway::VoucherRail for Channel {
        async fn accept(
            &self,
            _voucher: &tenzro_types::payment_authorization::EscrowVoucher,
            _payee: &tenzro_types::Address,
            charge: u128,
        ) -> crate::Result<RailOutcome> {
            self.0.lock().unwrap().push(charge);
            Ok(RailOutcome::Settled {
                reference: "escrow".to_string(),
            })
        }

        async fn check(
            &self,
            _voucher: &tenzro_types::payment_authorization::EscrowVoucher,
            _payee: &tenzro_types::Address,
            _charge: u128,
        ) -> crate::Result<RailOutcome> {
            Ok(RailOutcome::Settled {
                reference: "escrow".to_string(),
            })
        }
    }

    /// A metered challenge offers both the signed ceiling and a voucher on a
    /// channel; a payer answering with a voucher is served and charged the
    /// metered cost on its channel, never the voucher's whole amount.
    #[tokio::test]
    async fn a_metered_challenge_takes_a_channel_voucher_and_charges_the_metered_cost() {
        use tenzro_crypto::composite::HybridSigner as _;
        let channel = Arc::new(Channel(std::sync::Mutex::new(Vec::new())));
        let gw = TenzroPaymentGateway::new(1337, Arc::new(crate::test_support::SeedKeys))
            .with_voucher_rail(channel.clone());
        let x402 = crate::x402::X402PaymentServer::new(
            1337,
            vec!["tenzro".to_string()],
            Arc::new(crate::test_support::SeedKeys),
        )
        .with_scheme(crate::x402::UPTO_SCHEME)
        .with_also_offered(crate::x402::BATCH_SETTLEMENT_SCHEME)
        .with_challenge_store(gw.challenge_store());
        gw.register_protocol(Arc::new(x402));
        let gw = Arc::new(gw);
        let challenge = gw
            .create_challenge("x402", "/v1/chat/completions", 1000, "TNZO", PAYEE)
            .await
            .unwrap();
        let offered: Vec<String> = crate::x402::wire::payment_required_for(&challenge)
            .accepts
            .iter()
            .map(|r| r.scheme.clone())
            .collect();
        assert_eq!(
            offered,
            vec!["upto".to_string(), "batch-settlement".to_string()]
        );

        let payer = signer();
        let escrow_id = [7u8; 32];
        let cumulative = 900u128;
        let signature = payer
            .sign(
                tenzro_crypto::composite::SignatureContext::EscrowVoucher,
                &tenzro_types::payment_authorization::escrow_voucher_preimage(
                    1337, &escrow_id, cumulative, &[0u8; 32],
                ),
            )
            .unwrap();
        let credential = PaymentCredential {
            credential_id: "v-1".into(),
            challenge_id: challenge.challenge_id.clone(),
            protocol: "x402".into(),
            payer_did: String::new(),
            payer_address: String::new(),
            amount: cumulative,
            asset: "TNZO".into(),
            signature: Some(signature),
            extra: std::collections::HashMap::from([
                ("scheme".to_string(), serde_json::json!("batch-settlement")),
                (
                    "escrow_id".to_string(),
                    serde_json::json!(hex::encode(escrow_id)),
                ),
                (
                    "cumulative_amount".to_string(),
                    serde_json::json!(cumulative.to_string()),
                ),
                (
                    "public_key".to_string(),
                    serde_json::json!(hex::encode(&payer.public_key().p256)),
                ),
            ]),
        };
        let store = gw.challenge_store();
        let middleware =
            PaymentGateMiddleware::new(gw, gate_config(), store).with_metered_settlement(true);
        let app = Router::new()
            .route("/v1/chat/completions", cost_handler(StatusCode::OK, "300"))
            .layer(axum::middleware::from_fn_with_state(
                middleware,
                payment_gate_handler,
            ));
        let resp = app
            .oneshot(paid_request(&encode(&credential)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(*channel.0.lock().unwrap(), vec![300]);
    }

    /// Counts the decisions it is asked for, and allows every one.
    struct CountingAdmission(std::sync::atomic::AtomicUsize);

    impl InferenceAdmission for CountingAdmission {
        fn decide(
            &self,
            _headers: &axum::http::HeaderMap,
            _model_id: Option<&str>,
        ) -> InferenceAccess {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            InferenceAccess::Allow
        }
    }

    fn oversized_chat() -> Request<Body> {
        let mut body = br#"{"model":"m","messages":[],"pad":""#.to_vec();
        body.extend(std::iter::repeat_n(b'a', 3 * 1024 * 1024));
        body.extend_from_slice(br#""}"#);
        Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    /// A body larger than its route accepts is refused before it is buffered
    /// for the admission decision, on the admission-only surface and behind
    /// the payment gate alike.
    #[tokio::test]
    async fn an_oversized_inference_body_is_refused_before_admission() {
        let counting = Arc::new(CountingAdmission(std::sync::atomic::AtomicUsize::new(0)));
        let admission: Arc<dyn InferenceAdmission> = counting.clone();
        let app = Router::new()
            .route("/v1/chat/completions", axum::routing::post(test_handler))
            .layer(axum::middleware::from_fn_with_state(
                admission.clone(),
                inference_admission_handler,
            ));
        let response = app.oneshot(oversized_chat()).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let gateway = gateway_with(RecordingRail::new(RailOutcome::Settled {
            reference: "0xtx".to_string(),
        }));
        let challenge_store = gateway.challenge_store();
        let middleware = PaymentGateMiddleware::new(gateway, gate_config(), challenge_store)
            .with_inference_admission(admission);
        let app = Router::new()
            .route("/v1/chat/completions", axum::routing::post(test_handler))
            .layer(axum::middleware::from_fn_with_state(
                middleware,
                payment_gate_handler,
            ));
        let response = app.oneshot(oversized_chat()).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(counting.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}
