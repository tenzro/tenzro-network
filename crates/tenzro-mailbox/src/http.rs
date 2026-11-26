//! The mailbox over HTTP: JSON requests under `/mailbox/v1`.
//!
//! ```text
//! GET  /mailbox/v1/info                         -> MailboxInfo
//! POST /mailbox/v1/deposit  Deposit             -> Receipt
//! POST /mailbox/v1/list     { auth }            -> { messages: [Receipt] }
//! POST /mailbox/v1/collect  { auth, id }        -> { receipt, sealed }
//! POST /mailbox/v1/ack      { auth, id }        -> {}
//! POST /mailbox/v1/policy   { auth, policy }    -> { epoch }
//! POST /mailbox/v1/prekeys/upload { auth, packages, last_resort } -> { held }
//! POST /mailbox/v1/prekeys/fetch  PrekeyFetch   -> { package, last_resort }
//! ```
//!
//! A refusal answers with its status and `{ "error": "<why>" }`; a failure
//! inside the mailbox answers with its status and a fixed text, and is
//! logged in full. A request body is refused once it passes what the largest
//! message can need, before it is held in memory. [`serve`] bounds the
//! connections, the time to send the request headers and the time a whole
//! request may take; each request runs on a blocking thread, since the
//! mailbox reads and writes its directory while it holds its lock, and only
//! so many run at once.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::error::MailboxError;
use crate::service::{Mailbox, MailboxInfo};
use crate::wire::{Auth, Deposit, DepositPolicy, PrekeyFetch, Receipt};

/// Room in a request body for everything but the sealed bytes: a voucher
/// with both signature legs, a sender proof and a capability, or a
/// recipient's proof.
const ENVELOPE_BYTES: usize = 32 * 1024;

/// What the HTTP side of a mailbox takes at once and how long it waits.
#[derive(Debug, Clone)]
pub struct HttpLimits {
    /// Connections served at once; one more is closed on accept.
    pub max_connections: usize,
    /// Requests running at once; one more is answered 503.
    pub max_in_flight: usize,
    /// Time a client has to send its request headers.
    pub header_read_timeout: Duration,
    /// Time a whole request may take, its body included.
    pub request_timeout: Duration,
}

impl Default for HttpLimits {
    /// 256 connections, 32 requests at once, 10 seconds for the headers and
    /// 30 seconds for a request.
    fn default() -> Self {
        Self {
            max_connections: 256,
            max_in_flight: 32,
            header_read_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Clone)]
struct AppState {
    mailbox: Arc<Mailbox>,
    in_flight: Arc<Semaphore>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ListRequest {
    auth: Auth,
}

#[derive(Debug, Serialize, Deserialize)]
struct ListResponse {
    messages: Vec<Receipt>,
}

#[derive(Debug, Serialize, Deserialize)]
struct MessageRequest {
    auth: Auth,
    id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PolicyRequest {
    auth: Auth,
    policy: DepositPolicy,
}

#[derive(Debug, Serialize, Deserialize)]
struct UploadRequest {
    auth: Auth,
    packages: Vec<Base64>,
    last_resort: Option<Base64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FetchResponse {
    #[serde(with = "crate::wire::base64_bytes")]
    package: Vec<u8>,
    last_resort: bool,
}

/// Bytes as base64 in JSON, as a list element.
#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
struct Base64(#[serde(with = "crate::wire::base64_bytes")] Vec<u8>);

#[derive(Debug, Serialize, Deserialize)]
struct CollectResponse {
    receipt: Receipt,
    #[serde(with = "crate::wire::base64_bytes")]
    sealed: Vec<u8>,
}

impl IntoResponse for MailboxError {
    fn into_response(self) -> Response {
        let refusal = |status: StatusCode, error: &MailboxError| {
            (
                status,
                Json(serde_json::json!({ "error": error.to_string() })),
            )
                .into_response()
        };
        // The text of a failure inside the mailbox can name the node it reads
        // the ledger from or a path on the operator's disk: it is logged, and
        // the caller gets only what kind of failure it was.
        let failure = |status: StatusCode, kind: &str, error: &MailboxError| {
            tracing::warn!("{kind}: {error}");
            (status, Json(serde_json::json!({ "error": kind }))).into_response()
        };
        match &self {
            Self::SizeClass { .. } => refusal(StatusCode::PAYLOAD_TOO_LARGE, &self),
            Self::Lifetime { .. } | Self::Recipient { .. } | Self::Policy(_) | Self::Prekeys(_) => {
                refusal(StatusCode::BAD_REQUEST, &self)
            }
            #[cfg(feature = "mls")]
            Self::Group(_) => refusal(StatusCode::BAD_REQUEST, &self),
            #[cfg(feature = "files")]
            Self::Files(_) => refusal(StatusCode::BAD_REQUEST, &self),
            Self::Full | Self::RecipientFull => refusal(StatusCode::INSUFFICIENT_STORAGE, &self),
            Self::RateLimited | Self::Recovering => refusal(StatusCode::TOO_MANY_REQUESTS, &self),
            Self::Spent => refusal(StatusCode::CONFLICT, &self),
            Self::Unpaid(_) => refusal(StatusCode::PAYMENT_REQUIRED, &self),
            Self::Unauthorized(_) => refusal(StatusCode::UNAUTHORIZED, &self),
            Self::NotAllowed(_) => refusal(StatusCode::FORBIDDEN, &self),
            Self::NotFound => refusal(StatusCode::NOT_FOUND, &self),
            Self::Busy => refusal(StatusCode::SERVICE_UNAVAILABLE, &self),
            Self::Ledger(_) | Self::Remote(_) => failure(
                StatusCode::BAD_GATEWAY,
                "the ledger could not be read",
                &self,
            ),
            Self::Signing(_) | Self::Store(_) | Self::Config(_) => failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the mailbox failed",
                &self,
            ),
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Runs `call` on a blocking thread, holding one of the in-flight places
/// until it ends, even past the request's timeout.
async fn off_thread<T, F>(state: &AppState, call: F) -> Result<T, MailboxError>
where
    T: Send + 'static,
    F: std::future::Future<Output = Result<T, MailboxError>> + Send + 'static,
{
    let place = state
        .in_flight
        .clone()
        .try_acquire_owned()
        .map_err(|_| MailboxError::Busy)?;
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let _place = place;
        handle.block_on(call)
    })
    .await
    .map_err(|e| MailboxError::Store(format!("request task: {e}")))?
}

async fn info(State(state): State<AppState>) -> Json<MailboxInfo> {
    Json(state.mailbox.info())
}

async fn deposit(
    State(state): State<AppState>,
    Json(deposit): Json<Deposit>,
) -> Result<Json<Receipt>, MailboxError> {
    let mailbox = state.mailbox.clone();
    off_thread(
        &state,
        async move { mailbox.deposit(&deposit, now_ms()).await },
    )
    .await
    .map(Json)
}

async fn list(
    State(state): State<AppState>,
    Json(request): Json<ListRequest>,
) -> Result<Json<ListResponse>, MailboxError> {
    let mailbox = state.mailbox.clone();
    let messages = off_thread(&state, async move {
        mailbox.list(&request.auth, now_ms()).await
    })
    .await?;
    Ok(Json(ListResponse { messages }))
}

async fn collect(
    State(state): State<AppState>,
    Json(request): Json<MessageRequest>,
) -> Result<Json<CollectResponse>, MailboxError> {
    let mailbox = state.mailbox.clone();
    let (receipt, sealed) = off_thread(&state, async move {
        mailbox.collect(&request.auth, &request.id, now_ms()).await
    })
    .await?;
    Ok(Json(CollectResponse { receipt, sealed }))
}

async fn ack(
    State(state): State<AppState>,
    Json(request): Json<MessageRequest>,
) -> Result<Json<serde_json::Value>, MailboxError> {
    let mailbox = state.mailbox.clone();
    off_thread(&state, async move {
        mailbox.ack(&request.auth, &request.id, now_ms()).await
    })
    .await?;
    Ok(Json(serde_json::json!({})))
}

async fn policy(
    State(state): State<AppState>,
    Json(request): Json<PolicyRequest>,
) -> Result<Json<serde_json::Value>, MailboxError> {
    let mailbox = state.mailbox.clone();
    let epoch = off_thread(&state, async move {
        mailbox
            .set_policy(&request.auth, &request.policy, now_ms())
            .await
    })
    .await?;
    Ok(Json(serde_json::json!({ "epoch": epoch })))
}

async fn upload_prekeys(
    State(state): State<AppState>,
    Json(request): Json<UploadRequest>,
) -> Result<Json<serde_json::Value>, MailboxError> {
    let mailbox = state.mailbox.clone();
    let held = off_thread(&state, async move {
        let packages: Vec<Vec<u8>> = request.packages.into_iter().map(|p| p.0).collect();
        let last_resort = request.last_resort.map(|p| p.0);
        mailbox
            .upload_prekeys(&request.auth, &packages, last_resort.as_deref(), now_ms())
            .await
    })
    .await?;
    Ok(Json(serde_json::json!({ "held": held })))
}

async fn fetch_prekey(
    State(state): State<AppState>,
    Json(fetch): Json<PrekeyFetch>,
) -> Result<Json<FetchResponse>, MailboxError> {
    let mailbox = state.mailbox.clone();
    let prekey = off_thread(&state, async move {
        mailbox.fetch_prekey(&fetch, now_ms()).await
    })
    .await?;
    Ok(Json(FetchResponse {
        package: prekey.package,
        last_resort: prekey.last_resort,
    }))
}

/// The mailbox's HTTP routes, with each request's body capped and its whole
/// run bounded by `limits`.
pub fn router(mailbox: Arc<Mailbox>, limits: &HttpLimits) -> Router {
    let takes = mailbox.info();
    let largest_message = takes.size_classes.into_iter().max().unwrap_or(0) as usize;
    let largest_upload = (takes.max_prekeys_per_recipient + 1) * takes.max_prekey_bytes;
    // Base64 carries three bytes in four characters.
    let body_limit = largest_message.max(largest_upload).div_ceil(3) * 4 + ENVELOPE_BYTES;
    let state = AppState {
        mailbox,
        in_flight: Arc::new(Semaphore::new(limits.max_in_flight)),
    };
    Router::new()
        .route("/mailbox/v1/info", get(info))
        .route("/mailbox/v1/deposit", post(deposit))
        .route("/mailbox/v1/list", post(list))
        .route("/mailbox/v1/collect", post(collect))
        .route("/mailbox/v1/ack", post(ack))
        .route("/mailbox/v1/policy", post(policy))
        .route("/mailbox/v1/prekeys/upload", post(upload_prekeys))
        .route("/mailbox/v1/prekeys/fetch", post(fetch_prekey))
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            limits.request_timeout,
        ))
        .with_state(state)
}

/// Serves `router` on `listener`, HTTP/1.1 only, with at most
/// `limits.max_connections` connections at once and
/// `limits.header_read_timeout` for each request's headers.
pub async fn serve(listener: tokio::net::TcpListener, router: Router, limits: &HttpLimits) {
    let connections = Arc::new(Semaphore::new(limits.max_connections));
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                tracing::warn!("accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(place) = connections.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let service = hyper_util::service::TowerToHyperService::new(router.clone());
        let header_read_timeout = limits.header_read_timeout;
        tokio::spawn(async move {
            let _place = place;
            let served = hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(header_read_timeout)
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .await;
            if let Err(e) = served {
                tracing::debug!("connection: {e}");
            }
        });
    }
}
