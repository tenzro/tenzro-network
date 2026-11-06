//! Serving models from an endpoint the operator already runs.
//!
//! An operator with an OpenAI-compatible serving stack (`/v1/chat/completions`,
//! `/v1/embeddings`, `/v1/images/generations`) joins the network as a provider
//! without moving their models onto this node's engines. The `[connector]`
//! section of the node's configuration names the endpoint and the models it
//! serves; the endpoint's API key, when it has one, is sealed to this
//! machine's hardware with `tenzro-node credentials set upstream`, or else
//! given unsealed in `TENZRO_UPSTREAM_API_KEY` or the section's `api_key`, and
//! is sent only to that endpoint.
//!
//! The node is otherwise the node: its hardware identity signs its
//! announcements and receipts, its pricing cards price the work, and its
//! access policy admits callers. Each connector model is flagged as served,
//! so the model heartbeat announces it under the operator's card, and a
//! request routed to it arrives on `tenzro/infer` like any other. Only the
//! step that runs the model differs: instead of this node's runtime, the
//! request is sent to the operator's endpoint, and the units billed are the
//! ones its response reports. The receipt is signed by
//! [`crate::inference_receipt::sign_local`] over the output returned and
//! those units, and the call is priced, settled and recorded by the same
//! functions a locally served call uses.
//!
//! A model the catalog lists is refused: the network pins its weights, and
//! this node cannot show the endpoint serves them. A connector model is
//! identified by its id under the engine
//! [`crate::inference_receipt::UPSTREAM_ENGINE`], and is offered at the
//! `none` and `receipt` verification levels only.
//!
//! Every call to the endpoint is bounded: by a total time for a whole
//! response, by an idle time between the chunks of a stream, and by a cap on
//! the calls in flight. The endpoint's URL and key are never logged or put in
//! an error a caller sees.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Json, Response};
use base64::Engine as _;
use bytes::Bytes;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tenzro_types::Visibility;
use tenzro_types::inference_verification::VerificationLevel;
use tenzro_types::model::BillableUnits;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::config::NodeConfig;
use crate::inference_receipt::{SamplingParams, Served};
use crate::node::TenzroNode;
use crate::rpc::{JsonRpcError, OpenAIChatRequest, json_error_response};

/// Longest a whole non-streamed response may take, by default.
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 120;
/// Longest a stream may go without a chunk, by default.
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 60;
/// Calls in flight to the endpoint at once, by default.
pub const DEFAULT_MAX_CONCURRENT: usize = 64;
/// The longest either time may be set to.
const MAX_TIMEOUT_SECS: u64 = 3_600;
/// The most calls in flight that may be configured.
const MAX_CONCURRENT: usize = 4_096;
/// The largest response body read from the endpoint, the cap the network puts
/// on an answer carried between nodes.
const MAX_RESPONSE_BYTES: usize = tenzro_iroh::MAX_INFER_BYTES;
/// The most of an error body read, and of its message passed on.
const MAX_ERROR_BYTES: usize = 16 * 1024;
const MAX_ERROR_MESSAGE: usize = 512;
/// The longest model id a connector announces.
const MAX_MODEL_ID_LEN: usize = 128;

/// The sampling the node's own runtime decodes with when a request sets none.
/// A connector sends these explicitly, so a network call means the same
/// thing whichever provider serves it and the receipt states the decode.
const DEFAULT_TEMPERATURE: f64 = 0.7;
const DEFAULT_TOP_P: f64 = 0.9;
const DEFAULT_MAX_TOKENS: u32 = 512;

/// The `[connector]` section of the node's configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorConfig {
    /// The endpoint's base URL, the one its paths hang from, such as
    /// `http://127.0.0.1:8000/v1`. No credentials in it: the key is given
    /// separately.
    pub upstream_url: String,
    /// The endpoint's API key, for an operator who neither seals it nor sets
    /// `TENZRO_UPSTREAM_API_KEY`; both of those win over it. Stored unsealed,
    /// at the operator's own risk, and never written back out.
    #[serde(default, skip_serializing)]
    pub api_key: Option<crate::credentials::ConfigSecret>,
    /// Longest a whole non-streamed response may take, seconds.
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
    /// Longest a stream may go without a chunk, seconds.
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    /// Calls in flight to the endpoint at once; a call past it is refused
    /// with 429 rather than queued.
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,
    /// The models the endpoint serves and the network ids they are offered
    /// under.
    pub models: Vec<UpstreamModelConfig>,
}

fn default_request_timeout() -> u64 {
    DEFAULT_REQUEST_TIMEOUT_SECS
}
fn default_idle_timeout() -> u64 {
    DEFAULT_IDLE_TIMEOUT_SECS
}
fn default_max_concurrent() -> usize {
    DEFAULT_MAX_CONCURRENT
}

/// One model the endpoint serves.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamModelConfig {
    /// The id the network calls it by. Not a catalog id.
    pub id: String,
    /// The name the endpoint knows it by, sent as `model`.
    pub upstream_model: String,
    /// The work it does.
    pub work: WorkClass,
    /// Its visibility; absent, the node's.
    #[serde(default)]
    pub visibility: Option<Visibility>,
}

/// The work a connector model does, which says the endpoint path it is
/// called on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkClass {
    /// `POST {upstream_url}/chat/completions`.
    Chat,
    /// `POST {upstream_url}/embeddings`.
    Embeddings,
    /// `POST {upstream_url}/images/generations`.
    Images,
}

impl WorkClass {
    fn as_str(self) -> &'static str {
        match self {
            WorkClass::Chat => "chat",
            WorkClass::Embeddings => "embeddings",
            WorkClass::Images => "images",
        }
    }
}

impl ConnectorConfig {
    /// Refuse a section the connector could not serve from.
    pub fn validate(&self) -> Result<(), String> {
        let url = reqwest::Url::parse(&self.upstream_url)
            .map_err(|e| format!("upstream_url does not parse: {e}"))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err("upstream_url must be http or https".into());
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err("upstream_url carries credentials; seal the key with \
                 `tenzro-node credentials set upstream` instead"
                .into());
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err("upstream_url takes no query or fragment".into());
        }
        for (name, secs) in [
            ("request_timeout_secs", self.request_timeout_secs),
            ("idle_timeout_secs", self.idle_timeout_secs),
        ] {
            if secs == 0 || secs > MAX_TIMEOUT_SECS {
                return Err(format!("{name} must be 1 to {MAX_TIMEOUT_SECS}"));
            }
        }
        if self.max_concurrent == 0 || self.max_concurrent > MAX_CONCURRENT {
            return Err(format!("max_concurrent must be 1 to {MAX_CONCURRENT}"));
        }
        if self.models.is_empty() {
            return Err("name at least one model under [[connector.models]]".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for m in &self.models {
            if m.id.is_empty()
                || m.id.len() > MAX_MODEL_ID_LEN
                || m.id.chars().any(|c| c.is_whitespace() || c.is_control())
            {
                return Err(format!(
                    "model id {:?} must be 1 to {MAX_MODEL_ID_LEN} characters with no \
                     whitespace",
                    m.id
                ));
            }
            if m.upstream_model.trim().is_empty() {
                return Err(format!("model {} names no upstream_model", m.id));
            }
            if !seen.insert(m.id.as_str()) {
                return Err(format!("model {} is listed twice", m.id));
            }
        }
        Ok(())
    }
}

/// A model this node serves from the operator's endpoint.
#[derive(Debug, Clone)]
pub struct UpstreamModel {
    pub id: String,
    pub upstream_model: String,
    pub work: WorkClass,
    visibility: Option<Visibility>,
}

/// The operator's endpoint and the models served from it.
pub struct Connector {
    base: String,
    key: Option<Zeroizing<String>>,
    models: BTreeMap<String, UpstreamModel>,
    request_timeout: Duration,
    idle_timeout: Duration,
    slots: Arc<Semaphore>,
}

impl std::fmt::Debug for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The URL and key stay out of every log line.
        f.debug_struct("Connector")
            .field("models", &self.models.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl Connector {
    /// The connector the configuration describes, with its API key read from
    /// this machine's sealed store, the environment or the section; `None`
    /// without a `[connector]` section.
    pub fn from_config(config: &NodeConfig) -> Result<Option<Self>, String> {
        let Some(section) = &config.connector else {
            return Ok(None);
        };
        section.validate()?;
        let key = crate::credentials::read(
            &config.data_dir,
            crate::credentials::Secret::Upstream,
            section.api_key.as_ref(),
        )?
        .map(|(key, source)| {
            info!(?source, "Upstream API key set");
            key
        });
        Ok(Some(Self::new(section, key)))
    }

    fn new(section: &ConnectorConfig, key: Option<Zeroizing<String>>) -> Self {
        Self {
            base: section.upstream_url.trim_end_matches('/').to_string(),
            key,
            models: section
                .models
                .iter()
                .map(|m| {
                    (
                        m.id.clone(),
                        UpstreamModel {
                            id: m.id.clone(),
                            upstream_model: m.upstream_model.clone(),
                            work: m.work,
                            visibility: m.visibility,
                        },
                    )
                })
                .collect(),
            request_timeout: Duration::from_secs(section.request_timeout_secs),
            idle_timeout: Duration::from_secs(section.idle_timeout_secs),
            slots: Arc::new(Semaphore::new(section.max_concurrent)),
        }
    }

    /// Flag every connector model as served, under its visibility. Refuses a
    /// model the installed catalog lists.
    pub fn register(
        &self,
        served: &dashmap::DashMap<String, Option<Visibility>>,
    ) -> Result<(), String> {
        if let Some(listed) = self
            .models
            .keys()
            .find(|id| tenzro_model::catalog::entry(id).is_some())
        {
            return Err(format!(
                "{listed} is a catalog model, whose weights the network pins; offer the \
                 endpoint's model under an id of its own"
            ));
        }
        for m in self.models.values() {
            served.insert(m.id.clone(), m.visibility);
            info!(model = %m.id, work = m.work.as_str(), "Serving from the operator's endpoint");
        }
        Ok(())
    }

    /// The connector model `id` names.
    pub fn model(&self, id: &str) -> Option<&UpstreamModel> {
        self.models.get(id)
    }

    fn url(&self, work: WorkClass) -> String {
        let path = match work {
            WorkClass::Chat => "chat/completions",
            WorkClass::Embeddings => "embeddings",
            WorkClass::Images => "images/generations",
        };
        format!("{}/{path}", self.base)
    }

    /// A POST of `body` for `work`, with the API key as a bearer token the
    /// HTTP stack never prints.
    fn post(
        &self,
        client: &reqwest::Client,
        work: WorkClass,
        body: &Value,
    ) -> reqwest::RequestBuilder {
        let mut request = client.post(self.url(work)).json(body);
        if let Some(key) = &self.key
            && let Ok(mut value) =
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", key.as_str()))
        {
            value.set_sensitive(true);
            request = request.header(reqwest::header::AUTHORIZATION, value);
        }
        request
    }

    fn slot(&self) -> Result<OwnedSemaphorePermit, UpstreamError> {
        self.slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| UpstreamError::Busy)
    }

    /// Send `body` and read the whole JSON answer, within the request time.
    async fn call(&self, work: WorkClass, body: &Value) -> Result<Value, UpstreamError> {
        let exchange = async {
            let response = self
                .post(crate::http_client::streaming(), work, body)
                .send()
                .await
                .map_err(transport)?;
            let response = refuse_status(response).await?;
            let bytes = read_capped(response, MAX_RESPONSE_BYTES).await?;
            serde_json::from_slice::<Value>(&bytes)
                .map_err(|e| UpstreamError::Malformed(format!("the answer is not JSON: {e}")))
        };
        tokio::time::timeout(self.request_timeout, exchange)
            .await
            .map_err(|_| UpstreamError::Timeout)?
    }
}

/// Why a call to the endpoint produced no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UpstreamError {
    /// Every call slot is in use.
    Busy,
    /// No connection, or the connection failed.
    Unreachable(String),
    /// No answer within the configured time.
    Timeout,
    /// The endpoint answered with an error status.
    Status { status: u16, message: String },
    /// The endpoint answered with something that is not the API's shape.
    Malformed(String),
}

impl UpstreamError {
    fn status(&self) -> StatusCode {
        match self {
            UpstreamError::Busy => StatusCode::TOO_MANY_REQUESTS,
            UpstreamError::Unreachable(_) | UpstreamError::Malformed(_) => StatusCode::BAD_GATEWAY,
            UpstreamError::Timeout => StatusCode::GATEWAY_TIMEOUT,
            // A request the endpoint refused is the caller's to fix; anything
            // else is the endpoint's failure.
            UpstreamError::Status { status, .. } if (400..500).contains(status) => {
                StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_REQUEST)
            }
            UpstreamError::Status { .. } => StatusCode::BAD_GATEWAY,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            UpstreamError::Busy => "connector_busy",
            UpstreamError::Unreachable(_) => "upstream_unreachable",
            UpstreamError::Timeout => "upstream_timeout",
            UpstreamError::Status { .. } => "upstream_error",
            UpstreamError::Malformed(_) => "upstream_malformed",
        }
    }

    fn message(&self) -> String {
        match self {
            UpstreamError::Busy => "every call slot to the serving endpoint is in use".into(),
            UpstreamError::Unreachable(why) => {
                format!("the serving endpoint is unreachable: {why}")
            }
            UpstreamError::Timeout => "the serving endpoint did not answer in time".into(),
            UpstreamError::Status { status, message } => {
                format!("the serving endpoint answered {status}: {message}")
            }
            UpstreamError::Malformed(why) => format!("the serving endpoint's answer: {why}"),
        }
    }

    fn response(&self) -> Response {
        json_error_response(self.status(), &self.message(), "server_error", self.code())
    }

    fn rpc(&self) -> JsonRpcError {
        JsonRpcError {
            code: match self {
                UpstreamError::Busy => -32005,
                _ => -32000,
            },
            message: self.message(),
            data: Some(json!({ "code": self.code() })),
        }
    }
}

/// A transport failure, without the URL reqwest would put in its message.
fn transport(e: reqwest::Error) -> UpstreamError {
    if e.is_timeout() {
        UpstreamError::Timeout
    } else {
        UpstreamError::Unreachable(e.without_url().to_string())
    }
}

/// Pass a success through; turn an error status into an error carrying the
/// endpoint's own message, bounded.
async fn refuse_status(response: reqwest::Response) -> Result<reqwest::Response, UpstreamError> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let body = read_capped(response, MAX_ERROR_BYTES)
        .await
        .unwrap_or_default();
    let parsed = serde_json::from_slice::<Value>(&body).ok();
    let message = parsed
        .as_ref()
        .and_then(|v| {
            v.pointer("/error/message")
                .or_else(|| v.get("error"))
                .or_else(|| v.get("message"))
                .or_else(|| v.get("detail"))
        })
        .map(|m| match m {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .unwrap_or_else(|| String::from_utf8_lossy(&body).into_owned());
    Err(UpstreamError::Status {
        status: status.as_u16(),
        message: message.chars().take(MAX_ERROR_MESSAGE).collect(),
    })
}

/// A response body, refused past `cap` bytes.
async fn read_capped(response: reqwest::Response, cap: usize) -> Result<Vec<u8>, UpstreamError> {
    let mut body = response.bytes_stream();
    let mut out = Vec::new();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(transport)?;
        if out.len() + chunk.len() > cap {
            return Err(UpstreamError::Malformed(format!(
                "the answer exceeds {cap} bytes"
            )));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// The decode a chat request asks for, with the node's defaults for what it
/// leaves out.
fn sampling_of(request: &OpenAIChatRequest, seed: u64) -> SamplingParams {
    SamplingParams {
        seed,
        temperature: request.temperature.unwrap_or(DEFAULT_TEMPERATURE),
        top_p: request.top_p.unwrap_or(DEFAULT_TOP_P),
        top_k: request.top_k,
        min_p: request.min_p,
        max_output_tokens: request.max_output_tokens().unwrap_or(DEFAULT_MAX_TOKENS),
        keyed_sampler: false,
    }
}

/// The chat request the endpoint is sent: the caller's conversation and
/// tools under the endpoint's name for the model, with the decode stated in
/// full. Fields only this network reads (the receipt nonce, verification,
/// provider pins) are not sent.
fn upstream_chat_body(
    model: &UpstreamModel,
    request: &OpenAIChatRequest,
    sampling: &SamplingParams,
    stream: bool,
) -> Value {
    let mut body = json!({
        "model": model.upstream_model,
        "messages": request.messages,
        "temperature": sampling.temperature,
        "top_p": sampling.top_p,
        "max_tokens": sampling.max_output_tokens,
        "seed": sampling.seed,
        "stream": stream,
    });
    let obj = body.as_object_mut().expect("an object");
    let mut put = |k: &str, v: Option<Value>| {
        if let Some(v) = v.filter(|v| !v.is_null()) {
            obj.insert(k.to_string(), v);
        }
    };
    put("tools", request.tools.as_ref().map(|t| json!(t)));
    put("tool_choice", request.tool_choice.clone());
    put(
        "parallel_tool_calls",
        request.parallel_tool_calls.map(Value::Bool),
    );
    put("stop", request.stop.as_ref().map(|s| json!(s)));
    put(
        "frequency_penalty",
        request.frequency_penalty.map(|v| json!(v)),
    );
    put(
        "presence_penalty",
        request.presence_penalty.map(|v| json!(v)),
    );
    put("top_k", sampling.top_k.map(|v| json!(v)));
    put("min_p", sampling.min_p.map(|v| json!(v)));
    put(
        "repetition_penalty",
        request.repetition_penalty.map(|v| json!(v)),
    );
    put("user", request.user.clone().map(Value::String));
    if stream {
        // The counts the call is billed on arrive in the stream's last chunk.
        put("stream_options", Some(json!({ "include_usage": true })));
    }
    body
}

/// The units a chat answer reports, read the way a forwarding node reads
/// them ([`crate::streaming::usage_units`]), so the units this node signs are
/// the ones the forwarding node bills.
fn reported_units(model_id: &str, answer: &Value) -> BillableUnits {
    crate::streaming::usage_units(answer).unwrap_or_else(|| {
        warn!(model = %model_id, "The serving endpoint reported no usage; the call is billed nothing");
        BillableUnits::default()
    })
}

/// Refuse a chat request the connector cannot serve as asked, before the
/// endpoint is called.
fn admit_chat(
    node: &Arc<TenzroNode>,
    model: &UpstreamModel,
    request: &OpenAIChatRequest,
    level: VerificationLevel,
) -> Result<(), Response> {
    let refuse = |status, message: String, code| {
        Err(json_error_response(
            status,
            &message,
            "invalid_request_error",
            code,
        ))
    };
    if model.work != WorkClass::Chat {
        return refuse(
            StatusCode::BAD_REQUEST,
            format!(
                "model '{}' serves {} work, not chat",
                model.id,
                model.work.as_str()
            ),
            "unsupported_work",
        );
    }
    if !matches!(level, VerificationLevel::None | VerificationLevel::Receipt) {
        return refuse(
            StatusCode::BAD_REQUEST,
            format!(
                "model '{}' is served from the operator's own endpoint, which answers at the \
                 none and receipt verification levels only",
                model.id
            ),
            "verification_unavailable",
        );
    }
    if request.verifiable.unwrap_or(false) {
        return Err(json_error_response(
            StatusCode::NOT_IMPLEMENTED,
            &format!(
                "model '{}' is served from the operator's own endpoint, which produces no \
                 verifiable commitment",
                model.id
            ),
            "server_error",
            "commitment_unavailable",
        ));
    }
    if let Some(pin) = request
        .jurisdiction
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        && !crate::rpc::local_claim_satisfies_pin(node, pin)
    {
        return refuse(
            StatusCode::PRECONDITION_FAILED,
            format!("This node does not satisfy jurisdiction pin '{pin}'"),
            "jurisdiction_not_satisfied",
        );
    }
    if request
        .jurisdiction_receipt
        .as_deref()
        .is_some_and(|v| v.eq_ignore_ascii_case("required"))
    {
        return refuse(
            StatusCode::PRECONDITION_FAILED,
            "a model served from the operator's own endpoint carries no jurisdiction receipt"
                .to_string(),
            "jurisdiction_receipt_unavailable",
        );
    }
    // The card must price a chat before one is served.
    if let Err(e) = crate::rpc::price_local_units(node, &model.id, &BillableUnits::tokens(1, 1)) {
        return refuse(StatusCode::PAYMENT_REQUIRED, e.message, "unpriced");
    }
    Ok(())
}

/// What the receipt of a chat commits to on the input side, computed as the
/// node's own runtime computes it.
fn chat_input(request: &OpenAIChatRequest) -> Result<String, Response> {
    let mut media: Vec<Vec<u8>> = Vec::new();
    for m in &request.messages {
        let Some(content) = m.content.as_ref() else {
            continue;
        };
        let mut bytes = content.image_bytes().map_err(|e| {
            json_error_response(
                StatusCode::BAD_REQUEST,
                &e,
                "invalid_request_error",
                "invalid_image_part",
            )
        })?;
        media.append(&mut bytes);
    }
    let messages: Vec<tenzro_model::ChatMessage> =
        request.messages.iter().map(|m| m.to_model()).collect();
    Ok(crate::inference_receipt::input_commitment(
        &messages, &media,
    ))
}

/// Serve `/v1/chat/completions` for `model` from the operator's endpoint:
/// forwarded, metered from the endpoint's usage, receipted and priced as a
/// locally served completion is.
pub(crate) async fn serve_chat(
    node: Arc<TenzroNode>,
    model: UpstreamModel,
    request: OpenAIChatRequest,
    level: VerificationLevel,
    seed: u64,
) -> Response {
    let Some(connector) = node.connector().cloned() else {
        return UpstreamError::Unreachable("this node has no connector".into()).response();
    };
    if let Err(refused) = admit_chat(&node, &model, &request, level) {
        return refused;
    }
    let input_commitment = match chat_input(&request) {
        Ok(c) => c,
        Err(refused) => return refused,
    };
    let slot = match connector.slot() {
        Ok(s) => s,
        Err(e) => return e.response(),
    };
    let sampling = sampling_of(&request, seed);
    let stream = request.stream.unwrap_or(false);
    let body = upstream_chat_body(&model, &request, &sampling, stream);
    let call = ChatCall {
        node,
        connector,
        model,
        nonce: request.receipt_nonce.clone(),
        input_commitment,
        sampling,
        level,
        bytes_in: serde_json::to_vec(&request.messages)
            .map(|b| b.len() as u64)
            .unwrap_or(0),
    };
    if stream {
        let include_usage = request
            .stream_options
            .as_ref()
            .and_then(|o| o.include_usage)
            .unwrap_or(false);
        call.stream(body, include_usage, slot).await
    } else {
        let response = call.whole(body).await;
        drop(slot);
        response
    }
}

/// One chat call to the endpoint and what its receipt states.
struct ChatCall {
    node: Arc<TenzroNode>,
    connector: Arc<Connector>,
    model: UpstreamModel,
    nonce: Option<String>,
    input_commitment: String,
    sampling: SamplingParams,
    level: VerificationLevel,
    bytes_in: u64,
}

impl ChatCall {
    /// Sign the receipt, price the call and record it. `Err` only when the
    /// request's level requires a receipt this node could not sign.
    async fn settle(
        &self,
        completion_id: &str,
        units: &BillableUnits,
        output_hash: String,
        bytes_out: u64,
        started: Instant,
    ) -> Result<(Option<crate::inference_receipt::InferenceReceipt>, u128), String> {
        let receipt = crate::inference_receipt::sign_local(
            &self.node,
            Served {
                model_id: &self.model.id,
                nonce: self.nonce.as_deref(),
                input_commitment: self.input_commitment.clone(),
                output_hash,
                units: units.clone(),
                sampling: self.sampling.clone(),
                commitment_hash: None,
                level: self.level,
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        let cost_wei = crate::verifiable_inference::priced(
            crate::rpc::price_served_tokens(&self.node, &self.model.id, units),
            crate::verifiable_inference::surcharge_bps(&self.node, self.level),
        );
        crate::rpc::record_local_generation(
            &self.node,
            &self.model.id,
            completion_id,
            units.clone(),
            self.bytes_in,
            bytes_out,
            cost_wei,
            started.elapsed().as_millis() as u64,
        );
        self.node.metrics().record_inference();
        Ok((receipt, cost_wei))
    }

    /// A non-streamed completion.
    async fn whole(self, body: Value) -> Response {
        let started = Instant::now();
        let mut answer = match self.connector.call(WorkClass::Chat, &body).await {
            Ok(a) => a,
            Err(e) => {
                warn!(model = %self.model.id, error = %e.message(), "The serving endpoint failed a chat");
                return e.response();
            }
        };
        if answer
            .get("choices")
            .and_then(Value::as_array)
            .is_none_or(|c| c.is_empty())
        {
            return UpstreamError::Malformed("the answer has no choices".into()).response();
        }
        let units = reported_units(&self.model.id, &answer);
        let completion_id = answer
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("chatcmpl-{}", uuid::Uuid::new_v4()));
        let obj = answer.as_object_mut().expect("checked above");
        // The caller asked for the network's id, and the answer names it.
        obj.insert("model".into(), json!(self.model.id));
        let output_hash = crate::forward_billing::completion_output_hash(&answer);
        let bytes_out = serde_json::to_vec(&answer)
            .map(|b| b.len() as u64)
            .unwrap_or(0);
        let (receipt, cost_wei) = match self
            .settle(&completion_id, &units, output_hash, bytes_out, started)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                return json_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &e,
                    "server_error",
                    "verification_failed",
                );
            }
        };
        let obj = answer.as_object_mut().expect("an object");
        obj.insert("cost_wei".into(), json!(cost_wei.to_string()));
        obj.insert("seed".into(), json!(self.sampling.seed));
        obj.insert(
            "generation_time_ms".into(),
            json!(started.elapsed().as_millis() as u64),
        );
        obj.insert("tenzro_receipt".into(), json!(receipt));
        Json(answer).into_response()
    }

    /// A streamed completion: the endpoint's chunks relayed as they arrive,
    /// then a finish chunk carrying the usage, the cost and the receipt.
    async fn stream(
        self,
        body: Value,
        include_usage: bool,
        slot: OwnedSemaphorePermit,
    ) -> Response {
        let started = Instant::now();
        let request = self
            .connector
            .post(crate::http_client::streaming(), WorkClass::Chat, &body);
        let opened = tokio::time::timeout(self.connector.request_timeout, async {
            refuse_status(request.send().await.map_err(transport)?).await
        })
        .await;
        let response = match opened {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                warn!(model = %self.model.id, error = %e.message(), "The serving endpoint refused a stream");
                return e.response();
            }
            Err(_) => return UpstreamError::Timeout.response(),
        };
        let idle = self.connector.idle_timeout;
        let mut chunks = response.bytes_stream();
        let events = async_stream::stream! {
            // Held for the stream's life: the endpoint is busy until it ends.
            let _slot = slot;
            let completion_id = format!("chatcmpl-{}", uuid::Uuid::new_v4());
            let created = chrono::Utc::now().timestamp();
            let mut frames = SseFrames::default();
            let mut output = crate::forward_billing::StreamedOutput::default();
            let mut usage: Option<Value> = None;
            let mut finish_reason = Value::Null;
            let mut received = 0usize;
            let mut failure: Option<UpstreamError> = None;
            'read: loop {
                let next = match tokio::time::timeout(idle, chunks.next()).await {
                    Err(_) => {
                        failure = Some(UpstreamError::Timeout);
                        break;
                    }
                    Ok(None) => {
                        failure = Some(UpstreamError::Malformed("the stream ended before [DONE]".into()));
                        break;
                    }
                    Ok(Some(Err(e))) => {
                        failure = Some(transport(e));
                        break;
                    }
                    Ok(Some(Ok(bytes))) => bytes,
                };
                received += next.len();
                if received > MAX_RESPONSE_BYTES {
                    failure = Some(UpstreamError::Malformed(format!("the stream exceeds {MAX_RESPONSE_BYTES} bytes")));
                    break;
                }
                for payload in frames.push(&next) {
                    if payload == "[DONE]" {
                        break 'read;
                    }
                    let Ok(mut chunk) = serde_json::from_str::<Value>(&payload) else {
                        continue;
                    };
                    if let Some(e) = chunk.get("error") {
                        failure = Some(UpstreamError::Status {
                            status: 502,
                            message: e.get("message").and_then(Value::as_str).unwrap_or("stream error").chars().take(MAX_ERROR_MESSAGE).collect(),
                        });
                        break 'read;
                    }
                    if let Some(u) = chunk.get("usage").filter(|u| !u.is_null()) {
                        usage = Some(u.clone());
                    }
                    let has_choices = chunk.get("choices").and_then(Value::as_array).is_some_and(|c| !c.is_empty());
                    if !has_choices {
                        // The usage chunk: its counts go out in the finish chunk.
                        continue;
                    }
                    let obj = chunk.as_object_mut().expect("parsed with choices");
                    obj.insert("id".into(), json!(completion_id));
                    obj.insert("model".into(), json!(self.model.id));
                    obj.remove("usage");
                    // The finish reason goes out once, in the finish chunk.
                    if let Some(choice) = obj.get_mut("choices").and_then(|c| c.get_mut(0)) {
                        if let Some(reason) = choice.get("finish_reason").filter(|r| !r.is_null()) {
                            finish_reason = reason.clone();
                        }
                        choice["finish_reason"] = Value::Null;
                    }
                    let data = chunk.to_string();
                    output.absorb(&data);
                    yield Ok::<_, std::convert::Infallible>(Event::default().data(data));
                }
            }
            if let Some(e) = failure {
                warn!(model = %self.model.id, error = %e.message(), "The serving endpoint's stream failed");
                let err = json!({ "error": { "message": e.message(), "type": "server_error", "code": e.code() } });
                yield Ok(Event::default().data(err.to_string()));
                yield Ok(Event::default().data("[DONE]"));
                return;
            }
            let usage_holder = json!({ "usage": usage.clone().unwrap_or(Value::Null) });
            let units = reported_units(&self.model.id, &usage_holder);
            let (receipt, receipt_error, cost_wei) = match self
                .settle(&completion_id, &units, output.output_hash(), received as u64, started)
                .await
            {
                Ok((r, c)) => (r, None, c),
                // The tokens are out; a receipt the caller asked for and this
                // node could not sign is reported in the finish chunk.
                Err(e) => (None, Some(e), 0),
            };
            let usage_block = usage.unwrap_or(Value::Null);
            let finish = json!({
                "id": completion_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": self.model.id,
                "choices": [{ "index": 0, "delta": {}, "finish_reason": finish_reason }],
                "usage": usage_block,
                "cost_wei": cost_wei.to_string(),
                "generation_time_ms": started.elapsed().as_millis() as u64,
                "seed": self.sampling.seed,
                "tenzro_receipt": receipt,
                "tenzro_receipt_error": receipt_error,
            });
            yield Ok(Event::default().data(finish.to_string()));
            if include_usage {
                let tail = json!({
                    "id": completion_id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": self.model.id,
                    "choices": [],
                    "usage": usage_block,
                    "cost_wei": cost_wei.to_string(),
                });
                yield Ok(Event::default().data(tail.to_string()));
            }
            yield Ok(Event::default().data("[DONE]"));
        };
        Sse::new(events)
            .keep_alive(axum::response::sse::KeepAlive::default())
            .into_response()
    }
}

/// Splits a server-sent event stream into the payloads of its `data:` lines.
#[derive(Default)]
struct SseFrames {
    pending: Vec<u8>,
}

impl SseFrames {
    fn push(&mut self, bytes: &Bytes) -> Vec<String> {
        self.pending.extend_from_slice(bytes);
        let mut out = Vec::new();
        while let Some(end) = self.pending.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=end).collect();
            let line = String::from_utf8_lossy(&line);
            let line = line.trim_end_matches(['\n', '\r']);
            if let Some(payload) = line.strip_prefix("data:") {
                out.push(payload.trim_start().to_string());
            }
        }
        out
    }
}

/// Serve a `tenzro_chat` frame for `model` from the operator's endpoint, in
/// the shape the node's own runtime answers it: forwarded as one user turn,
/// metered from the endpoint's usage, receipted and settled.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_chat_frame(
    node: &Arc<TenzroNode>,
    model: &UpstreamModel,
    params: &Value,
    message: &str,
    config: &tenzro_model::GenerationConfig,
    verifiable: bool,
    level: VerificationLevel,
    jurisdiction_pin: Option<&str>,
    jurisdiction_receipt_required: bool,
) -> Result<Value, JsonRpcError> {
    let refuse = |code: i32, message: String| JsonRpcError {
        code,
        message,
        data: None,
    };
    let connector = node
        .connector()
        .cloned()
        .ok_or_else(|| refuse(-32000, "this node has no connector".into()))?;
    if model.work != WorkClass::Chat {
        return Err(refuse(
            -32602,
            format!(
                "model '{}' serves {} work, not chat",
                model.id,
                model.work.as_str()
            ),
        ));
    }
    if !matches!(level, VerificationLevel::None | VerificationLevel::Receipt) || verifiable {
        return Err(refuse(
            -32021,
            format!(
                "model '{}' is served from the operator's own endpoint, which answers at the \
                 none and receipt verification levels only",
                model.id
            ),
        ));
    }
    if let Some(pin) = jurisdiction_pin
        && !crate::rpc::local_claim_satisfies_pin(node, pin)
    {
        return Err(refuse(
            -32024,
            format!("This node does not satisfy jurisdiction pin '{pin}'"),
        ));
    }
    if jurisdiction_receipt_required {
        return Err(refuse(
            -32024,
            "a model served from the operator's own endpoint carries no jurisdiction receipt"
                .into(),
        ));
    }
    crate::rpc::price_local_units(node, &model.id, &BillableUnits::tokens(1, 1))?;
    let _slot = connector.slot().map_err(|e| e.rpc())?;
    let messages = vec![tenzro_model::ChatMessage {
        role: "user".to_string(),
        content: message.to_string(),
        ..Default::default()
    }];
    let sampling = SamplingParams::from_config(config);
    let mut body = json!({
        "model": model.upstream_model,
        "messages": [{ "role": "user", "content": message }],
        "temperature": sampling.temperature,
        "top_p": sampling.top_p,
        "max_tokens": sampling.max_output_tokens,
        "seed": sampling.seed,
        "stream": false,
    });
    if let Some(obj) = body.as_object_mut() {
        if let Some(k) = sampling.top_k {
            obj.insert("top_k".into(), json!(k));
        }
        if let Some(p) = sampling.min_p {
            obj.insert("min_p".into(), json!(p));
        }
        if !config.stop.is_empty() {
            obj.insert("stop".into(), json!(config.stop));
        }
    }
    let started = Instant::now();
    let answer = connector
        .call(WorkClass::Chat, &body)
        .await
        .map_err(|e| e.rpc())?;
    let msg = answer
        .pointer("/choices/0/message")
        .ok_or_else(|| UpstreamError::Malformed("the answer has no message".into()).rpc())?;
    let output = msg
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let thinking = msg
        .get("reasoning_content")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
        .map(str::to_string);
    let units = reported_units(&model.id, &answer);
    let cost_wei = crate::verifiable_inference::priced(
        crate::rpc::price_local_units(node, &model.id, &units)?,
        crate::verifiable_inference::surcharge_bps(node, level),
    );
    let settlement = crate::rpc::settle_inference_cost(
        node,
        params.get("payment"),
        params.get("channel_voucher"),
        None,
        &model.id,
        &units,
        cost_wei,
    )
    .await?;
    let receipt = crate::inference_receipt::sign_local(
        node,
        Served {
            model_id: &model.id,
            nonce: params.get("receipt_nonce").and_then(Value::as_str),
            input_commitment: crate::inference_receipt::input_commitment(&messages, &[]),
            output_hash: crate::inference_receipt::output_hash(
                &output,
                thinking.as_deref().unwrap_or(""),
                "",
            ),
            units: units.clone(),
            sampling,
            commitment_hash: None,
            level,
        },
    )
    .await
    .map_err(crate::verifiable_inference::receipt_refused)?;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    crate::rpc::record_local_generation(
        node,
        &model.id,
        &uuid::Uuid::new_v4().to_string(),
        units.clone(),
        message.len() as u64,
        output.len() as u64,
        cost_wei,
        elapsed_ms,
    );
    node.metrics().record_inference();
    Ok(json!({
        "tenzro_receipt": receipt,
        "output": output,
        "thinking": thinking,
        "input_tokens": units.input_tokens() + units.cached_read_tokens(),
        "output_tokens": units.output_tokens(),
        "units": crate::rpc::units_to_json(&units),
        "generation_time_ms": elapsed_ms,
        "cost_wei": cost_wei.to_string(),
        "settlement": settlement.to_json(),
        "model_id": model.id,
        "location": "upstream",
    }))
}

/// Serve `tenzro_textEmbed` for `model` from the endpoint's `/embeddings`,
/// in the shape and under the receipt and settlement the node's own encoders
/// answer with.
pub(crate) async fn serve_text_embed(
    node: &Arc<TenzroNode>,
    model: &UpstreamModel,
    p: Value,
) -> Result<Value, JsonRpcError> {
    let invalid = |message: String| JsonRpcError {
        code: -32602,
        message,
        data: None,
    };
    let connector = node
        .connector()
        .cloned()
        .ok_or_else(|| UpstreamError::Unreachable("this node has no connector".into()).rpc())?;
    if model.work != WorkClass::Embeddings {
        return Err(invalid(format!(
            "model '{}' serves {} work, not embeddings",
            model.id,
            model.work.as_str()
        )));
    }
    let level = upstream_task_level(&p, &model.id)?;
    let inputs: Vec<String> = p
        .get("inputs")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("'inputs' must be a non-empty array".into()))?
        .iter()
        .map(|i| match i {
            Value::String(s) => Ok(s.clone()),
            Value::Object(o) if o.len() == 1 && o.get("text").is_some_and(Value::is_string) => {
                Ok(o["text"].as_str().unwrap_or_default().to_string())
            }
            _ => Err(invalid(format!(
                "model '{}' is served from the operator's endpoint, which embeds text inputs only",
                model.id
            ))),
        })
        .collect::<Result<_, _>>()?;
    if inputs.is_empty() {
        return Err(invalid("'inputs' must be a non-empty array".into()));
    }
    let requested_dim = p.get("requested_dim").and_then(Value::as_u64);
    let normalize = p.get("normalize").and_then(Value::as_bool).unwrap_or(false);
    let _slot = connector.slot().map_err(|e| e.rpc())?;
    let mut body = json!({
        "model": model.upstream_model,
        "input": inputs,
        "encoding_format": "float",
    });
    if let Some(dim) = requested_dim {
        body["dimensions"] = json!(dim);
    }
    let started = Instant::now();
    let answer = connector
        .call(WorkClass::Embeddings, &body)
        .await
        .map_err(|e| e.rpc())?;
    let mut rows: Vec<(u64, Vec<f32>)> = answer
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| UpstreamError::Malformed("the answer has no data".into()).rpc())?
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let index = row.get("index").and_then(Value::as_u64).unwrap_or(i as u64);
            let vector = row
                .get("embedding")
                .and_then(Value::as_array)
                .map(|v| {
                    v.iter()
                        .filter_map(Value::as_f64)
                        .map(|x| x as f32)
                        .collect()
                })
                .unwrap_or_default();
            (index, vector)
        })
        .collect();
    rows.sort_by_key(|(i, _)| *i);
    let mut embeddings: Vec<Vec<f32>> = rows.into_iter().map(|(_, v)| v).collect();
    if embeddings.len() != inputs.len() || embeddings.iter().any(Vec::is_empty) {
        return Err(UpstreamError::Malformed(format!(
            "{} embeddings for {} inputs",
            embeddings.len(),
            inputs.len()
        ))
        .rpc());
    }
    if normalize {
        for v in &mut embeddings {
            let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
            if norm > 0.0 {
                v.iter_mut().for_each(|x| *x /= norm);
            }
        }
    }
    let prompt_tokens = answer
        .pointer("/usage/prompt_tokens")
        .and_then(Value::as_u64)
        .map(|t| t.min(u64::from(u32::MAX)) as u32)
        .unwrap_or_else(|| {
            warn!(model = %model.id, "The serving endpoint reported no usage; the call is billed nothing");
            0
        });
    // The shape the node's own encoders answer with, written out here so
    // the light build, which has no encoders, serves it too.
    let generation_time_ms = started.elapsed().as_millis() as u64;
    let dim = embeddings[0].len();
    let units = BillableUnits::tokens(prompt_tokens, 0);
    let bytes_in = inputs.iter().map(|s| s.len() as u64).sum();
    let bytes_out =
        (embeddings.iter().map(Vec::len).sum::<usize>() * std::mem::size_of::<f32>()) as u64;
    let (cost_wei, settlement) = crate::rpc::bill_local_units(
        node,
        &p,
        &model.id,
        units.clone(),
        bytes_in,
        bytes_out,
        generation_time_ms,
    )
    .await?;
    let mut out = json!({
        "embeddings": embeddings,
        "dim": dim,
        "prompt_tokens": prompt_tokens,
        "generation_time_ms": generation_time_ms,
    });
    crate::verifiable_inference::attach_task_receipt(
        node,
        &p,
        &model.id,
        "text_embed",
        level,
        units.clone(),
        &mut out,
    )
    .await?;
    if let Some(obj) = out.as_object_mut() {
        obj.insert("units".into(), crate::rpc::units_to_json(&units));
        obj.insert("cost_wei".into(), json!(cost_wei.to_string()));
        obj.insert("settlement".into(), settlement.to_json());
    }
    Ok(out)
}

/// Serve `tenzro_mediaGen_render` of a still image for `model` from the
/// endpoint's `/images/generations`, under the commitments, receipt and
/// settlement a render on the node's own media models carries. The units are
/// the images the endpoint returned.
pub(crate) async fn serve_render(
    node: &Arc<TenzroNode>,
    model: &UpstreamModel,
    p: &Value,
) -> Result<Value, JsonRpcError> {
    use tenzro_types::media_gen::{MediaGenKind, MediaGenParams};
    let invalid = |message: String| JsonRpcError {
        code: -32602,
        message,
        data: None,
    };
    let connector = node
        .connector()
        .cloned()
        .ok_or_else(|| UpstreamError::Unreachable("this node has no connector".into()).rpc())?;
    if model.work != WorkClass::Images {
        return Err(invalid(format!(
            "model '{}' serves {} work, not images",
            model.id,
            model.work.as_str()
        )));
    }
    let level = upstream_task_level(p, &model.id)?;
    let kind: MediaGenKind = serde_json::from_value(
        p.get("kind")
            .cloned()
            .ok_or_else(|| invalid("missing 'kind'".into()))?,
    )
    .map_err(|e| invalid(format!("'kind': {e}")))?;
    if kind != MediaGenKind::Text2Image {
        return Err(invalid(format!(
            "model '{}' is served from the operator's endpoint, which renders text2image only",
            model.id
        )));
    }
    let media: MediaGenParams = serde_json::from_value(
        p.get("params")
            .cloned()
            .ok_or_else(|| invalid("missing 'params'".into()))?,
    )
    .map_err(|e| invalid(format!("'params': {e}")))?;
    media
        .validate_for(kind)
        .map_err(|e| invalid(e.to_string()))?;
    let seed = media
        .seed
        .ok_or_else(|| invalid("a render is seeded: set params.seed".into()))?;
    let _slot = connector.slot().map_err(|e| e.rpc())?;
    let body = json!({
        "model": model.upstream_model,
        "prompt": media.prompt,
        "n": 1,
        "size": format!("{}x{}", media.width, media.height),
        "response_format": "b64_json",
        "seed": seed,
    });
    let started = Instant::now();
    let answer = connector
        .call(WorkClass::Images, &body)
        .await
        .map_err(|e| e.rpc())?;
    let images = answer
        .get("data")
        .and_then(Value::as_array)
        .filter(|d| !d.is_empty())
        .ok_or_else(|| UpstreamError::Malformed("the answer has no images".into()).rpc())?;
    let encoded = images[0]
        .get("b64_json")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            UpstreamError::Malformed("the image is not returned as b64_json".into()).rpc()
        })?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| UpstreamError::Malformed(format!("the image is not base64: {e}")).rpc())?;
    let png = as_png(bytes).map_err(|e| UpstreamError::Malformed(e).rpc())?;
    let out_bytes = png.len() as u64;
    let mut out = crate::media_verify::committed("image/png", &png)
        .map_err(|e| UpstreamError::Malformed(e).rpc())?;
    let mut units = BillableUnits::default();
    units
        .set(tenzro_types::meter::unit::IMAGES, images.len() as u128)
        .expect("a registered unit");
    crate::verifiable_inference::attach_task_receipt(
        node,
        p,
        &model.id,
        "media",
        level,
        units.clone(),
        &mut out,
    )
    .await?;
    let blake3 = {
        use tenzro_iroh::IrohResolver as _;
        let resolver = node.iroh_resolver.as_ref().ok_or_else(|| JsonRpcError {
            code: -32603,
            message: "this node has no content store to hold the output".into(),
            data: None,
        })?;
        match resolver
            .publish_bytes(png.into())
            .await
            .map_err(|e| JsonRpcError {
                code: -32603,
                message: format!("storing the output: {e}"),
                data: None,
            })? {
            tenzro_types::tenzro_uri::TenzroUri::Blob { hash, .. } => hash,
            other => {
                return Err(JsonRpcError {
                    code: -32603,
                    message: format!("the content store answered {other:?}"),
                    data: None,
                });
            }
        }
    };
    let (cost_wei, settlement) = crate::rpc::bill_local_units(
        node,
        p,
        &model.id,
        units.clone(),
        0,
        out_bytes,
        started.elapsed().as_millis() as u64,
    )
    .await?;
    if let Some(obj) = out.as_object_mut() {
        obj.insert("output_blake3".into(), json!(blake3));
        obj.insert("units".into(), crate::rpc::units_to_json(&units));
        obj.insert("cost_wei".into(), json!(cost_wei.to_string()));
        obj.insert("settlement".into(), settlement.to_json());
    }
    Ok(out)
}

/// The verification a task call asks for, refused above `receipt`.
fn upstream_task_level(p: &Value, model_id: &str) -> Result<VerificationLevel, JsonRpcError> {
    let level = crate::verifiable_inference::level_param(p.get("verification"))?;
    if matches!(level, VerificationLevel::None | VerificationLevel::Receipt) {
        Ok(level)
    } else {
        Err(JsonRpcError {
            code: -32021,
            message: format!(
                "model '{model_id}' is served from the operator's own endpoint, which answers at \
                 the none and receipt verification levels only"
            ),
            data: None,
        })
    }
}

/// An image as PNG, the format a render commits to; other formats the
/// endpoint returns are re-encoded.
fn as_png(bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";
    if bytes.starts_with(PNG_MAGIC) {
        return Ok(bytes);
    }
    let image =
        image::load_from_memory(&bytes).map_err(|e| format!("the image does not decode: {e}"))?;
    let mut png = std::io::Cursor::new(Vec::new());
    image
        .write_to(&mut png, image::ImageFormat::Png)
        .map_err(|e| format!("re-encoding the image: {e}"))?;
    Ok(png.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(models: Vec<UpstreamModelConfig>) -> ConnectorConfig {
        ConnectorConfig {
            upstream_url: "http://127.0.0.1:8000/v1".into(),
            request_timeout_secs: 5,
            idle_timeout_secs: 5,
            max_concurrent: 2,
            api_key: None,
            models,
        }
    }

    fn chat(id: &str) -> UpstreamModelConfig {
        UpstreamModelConfig {
            id: id.into(),
            upstream_model: "served-name".into(),
            work: WorkClass::Chat,
            visibility: None,
        }
    }

    #[test]
    fn the_section_parses_from_toml() {
        let parsed: ConnectorConfig = toml::from_str(
            r#"
            upstream_url = "http://127.0.0.1:8000/v1"
            [[models]]
            id = "acme/chat-70b"
            upstream_model = "meta-llama/Llama-3.1-70B-Instruct"
            work = "chat"
            [[models]]
            id = "acme/embed"
            upstream_model = "bge"
            work = "embeddings"
            visibility = "gated"
            "#,
        )
        .unwrap();
        parsed.validate().unwrap();
        assert_eq!(parsed.request_timeout_secs, DEFAULT_REQUEST_TIMEOUT_SECS);
        assert_eq!(parsed.idle_timeout_secs, DEFAULT_IDLE_TIMEOUT_SECS);
        assert_eq!(parsed.max_concurrent, DEFAULT_MAX_CONCURRENT);
        assert_eq!(parsed.models[1].work, WorkClass::Embeddings);
        assert_eq!(parsed.models[1].visibility, Some(Visibility::Gated));
    }

    #[test]
    fn a_section_the_connector_cannot_serve_from_is_refused() {
        let mut s = section(vec![chat("acme/a")]);
        s.validate().unwrap();
        for (url, why) in [
            ("ftp://host/v1", "http or https"),
            ("http://user:pw@host/v1", "credentials"),
            ("http://host/v1?key=x", "query"),
            ("not a url", "does not parse"),
        ] {
            s.upstream_url = url.into();
            assert!(s.validate().unwrap_err().contains(why), "{url}");
        }
        let mut s = section(vec![chat("acme/a"), chat("acme/a")]);
        assert!(s.validate().unwrap_err().contains("twice"));
        s.models = vec![chat("has space")];
        assert!(s.validate().is_err());
        s.models = Vec::new();
        assert!(s.validate().is_err());
        let mut s = section(vec![chat("acme/a")]);
        s.idle_timeout_secs = 0;
        assert!(s.validate().is_err());
        s.idle_timeout_secs = 5;
        s.max_concurrent = 0;
        assert!(s.validate().is_err());
    }

    #[test]
    fn a_catalog_model_is_not_served_from_an_endpoint() {
        tenzro_catalog::install_test_seed();
        let served = dashmap::DashMap::new();
        let c = Connector::new(&section(vec![chat("qwen3-0.6b")]), None);
        assert!(c.register(&served).unwrap_err().contains("catalog model"));
        assert!(served.is_empty());
        let c = Connector::new(&section(vec![chat("acme/own-model")]), None);
        c.register(&served).unwrap();
        assert!(served.contains_key("acme/own-model"));
    }

    #[test]
    fn the_key_and_url_never_print() {
        let c = Connector::new(
            &section(vec![chat("acme/a")]),
            Some(Zeroizing::new("sk-secret-key".into())),
        );
        let shown = format!("{c:?}");
        assert!(
            !shown.contains("sk-secret-key") && !shown.contains("127.0.0.1"),
            "{shown}"
        );
        let request = c
            .post(&reqwest::Client::new(), WorkClass::Chat, &json!({}))
            .build()
            .unwrap();
        assert_eq!(
            request.url().as_str(),
            "http://127.0.0.1:8000/v1/chat/completions"
        );
        let auth = request
            .headers()
            .get(reqwest::header::AUTHORIZATION)
            .unwrap();
        assert!(auth.is_sensitive());
        assert!(!format!("{request:?}").contains("sk-secret-key"));
    }

    #[test]
    fn sse_frames_split_across_chunks_reassemble() {
        let mut f = SseFrames::default();
        assert!(f.push(&Bytes::from_static(b"data: {\"a\"")).is_empty());
        assert_eq!(
            f.push(&Bytes::from_static(b":1}\r\n\r\n: keepalive\n")),
            vec!["{\"a\":1}"]
        );
        assert_eq!(
            f.push(&Bytes::from_static(b"event: x\ndata: [DONE]\n\n")),
            vec!["[DONE]"]
        );
    }

    #[test]
    fn an_endpoint_error_maps_to_a_bounded_answer() {
        let e = UpstreamError::Status {
            status: 400,
            message: "x".repeat(10),
        };
        assert_eq!(e.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            UpstreamError::Status {
                status: 503,
                message: String::new()
            }
            .status(),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(UpstreamError::Timeout.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(UpstreamError::Busy.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn a_non_png_image_is_re_encoded() {
        let img = image::RgbImage::from_pixel(4, 4, image::Rgb([10, 20, 30]));
        let mut jpeg = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut jpeg, image::ImageFormat::Jpeg)
            .unwrap();
        let png = as_png(jpeg.into_inner()).unwrap();
        assert!(png.starts_with(b"\x89PNG"));
        assert!(as_png(b"not an image".to_vec()).is_err());
    }
}
