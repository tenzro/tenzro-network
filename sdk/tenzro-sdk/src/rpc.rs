//! JSON-RPC 2.0 client for Tenzro Network
//!
//! Provides the low-level transport for all SDK calls to a Tenzro node.

use crate::access::AccessCredential;
use crate::error::{SdkError, SdkResult};
use serde::{Serialize, de::DeserializeOwned};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// JSON-RPC 2.0 request
#[derive(Debug, Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'a str,
    method: &'a str,
    params: serde_json::Value,
    id: u64,
}

/// A failed HTTP exchange as a connection error carrying the whole chain of
/// causes, so "error sending request" says what the connect, the TLS
/// handshake or the proxy refused.
fn connection_error(e: &(dyn std::error::Error + 'static)) -> SdkError {
    let mut text = e.to_string();
    let mut cause = e.source();
    while let Some(c) = cause {
        text.push_str(": ");
        text.push_str(&c.to_string());
        cause = c.source();
    }
    SdkError::ConnectionError(text)
}

/// The result of a JSON-RPC 2.0 response, or the node's error. A `null`
/// result is a result: it decodes into `T` (an `Option` reads it as `None`),
/// and only a response with neither `result` nor `error` is malformed.
fn decode_response<T: DeserializeOwned>(mut response: serde_json::Value) -> SdkResult<T> {
    let Some(body) = response.as_object_mut() else {
        return Err(SdkError::RpcError(
            "Failed to parse response: not a JSON-RPC object".to_string(),
        ));
    };
    if let Some(err) = body.remove("error").filter(|e| !e.is_null()) {
        let err: crate::error::NodeError = serde_json::from_value(err)
            .map_err(|e| SdkError::RpcError(format!("Failed to parse response error: {e}")))?;
        return Err(SdkError::Node(err));
    }
    let result = body
        .remove("result")
        .ok_or_else(|| SdkError::RpcError("Response missing result field".to_string()))?;
    serde_json::from_value(result)
        .map_err(|e| SdkError::RpcError(format!("Failed to parse response: {e}")))
}

/// `req` carrying a DPoP proof from `prover` for a POST to `url` and no
/// access token.
fn proved_only(
    req: reqwest::RequestBuilder,
    url: &str,
    prover: &dyn crate::access::DpopProver,
) -> SdkResult<reqwest::RequestBuilder> {
    Ok(req.header("DPoP", prover.proof("POST", url, "")?))
}

/// JSON-RPC client for communicating with a Tenzro node.
///
/// Talks to the node over HTTP (`reqwest` against an `http(s)://...`
/// endpoint).
///
/// A client carries at most one access credential, presented with a fresh
/// DPoP proof on every request it makes. A caller signed in as several DIDs
/// builds one client per DID.
#[derive(Clone)]
pub struct RpcClient {
    backend: RpcBackend,
    request_id: Arc<AtomicU64>,
    credential: Option<AccessCredential>,
}

/// Transport backend for [`RpcClient`].
#[derive(Clone)]
enum RpcBackend {
    /// HTTP JSON-RPC against a remote node. The default.
    Http {
        http: reqwest::Client,
        /// Same pool without the whole-request timeout, for streamed
        /// responses that legitimately outlive it.
        streaming: reqwest::Client,
        endpoint: String,
        /// Further endpoints a call moves to, in order, when the one before
        /// cannot be reached or times out (see [`RpcClient::with_failover`]).
        failover: Arc<Vec<String>>,
    },
}

impl RpcClient {
    /// Creates a new HTTP RPC client, signed in when `credential` is given.
    pub fn new(
        endpoint: &str,
        timeout: Duration,
        credential: Option<AccessCredential>,
    ) -> SdkResult<Self> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| connection_error(&e))?;
        let streaming = reqwest::Client::builder()
            .connect_timeout(timeout)
            .build()
            .map_err(|e| connection_error(&e))?;

        Ok(Self {
            backend: RpcBackend::Http {
                http,
                streaming,
                endpoint: endpoint.to_string(),
                failover: Arc::new(Vec::new()),
            },
            request_id: Arc::new(AtomicU64::new(0)),
            credential,
        })
    }

    /// An HTTP client over several endpoints of one network: each JSON-RPC
    /// call goes to the first and moves to the next when one cannot be
    /// reached or times out. A JSON-RPC error is the node's answer and is
    /// returned as is. It carries no access credential, so it serves open
    /// methods and signed transactions, which every operator accepts on
    /// their own signature. See [`crate::network`] for finding the endpoints.
    pub fn with_failover(endpoints: Vec<String>, timeout: Duration) -> SdkResult<Self> {
        let mut endpoints = endpoints.into_iter();
        let first = endpoints.next().ok_or_else(|| {
            SdkError::InvalidParameter("with_failover needs at least one endpoint".into())
        })?;
        let mut client = Self::new(&first, timeout, None)?;
        let RpcBackend::Http { failover, .. } = &mut client.backend;
        *failover = Arc::new(endpoints.collect());
        Ok(client)
    }

    /// Attach this client's access token and a DPoP proof for this request.
    /// Without a credential, `TENZRO_BEARER_JWT` and `TENZRO_DPOP_PROOF` are
    /// forwarded when set.
    fn authorized(
        &self,
        htm: &str,
        url: &str,
        req: reqwest::RequestBuilder,
    ) -> SdkResult<reqwest::RequestBuilder> {
        let (token, proof) = match &self.credential {
            Some(c) => (
                Some(c.token.clone()),
                Some(c.prover.proof(htm, url, &c.token)?),
            ),
            None => (
                env_nonempty("TENZRO_BEARER_JWT"),
                env_nonempty("TENZRO_DPOP_PROOF"),
            ),
        };
        let mut req = req;
        if let Some(t) = token {
            req = req.header("Authorization", format!("DPoP {t}"));
        }
        if let Some(p) = proof {
            req = req.header("DPoP", p);
        }
        Ok(req)
    }

    /// POST a JSON body to `path` on the node's RPC origin and hand back the
    /// response unread, for callers that consume a streamed body. A non-2xx
    /// status becomes the node's `{"error":{..}}` as [`SdkError::Api`] when
    /// the body carries one.
    pub async fn post_stream<B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> SdkResult<reqwest::Response> {
        self.open_route(path, |req| req.json(body)).await
    }

    /// POST a body that is sent while it is produced (newline-delimited
    /// JSON) to `path`, and hand back the streamed response unread.
    pub async fn post_body_stream(
        &self,
        path: &str,
        body: reqwest::Body,
    ) -> SdkResult<reqwest::Response> {
        self.open_route(path, |req| {
            req.header("Content-Type", "application/x-ndjson")
                .body(body)
        })
        .await
    }

    async fn open_route(
        &self,
        path: &str,
        fill: impl FnOnce(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
    ) -> SdkResult<reqwest::Response> {
        let (streaming, endpoint) = match &self.backend {
            RpcBackend::Http {
                streaming,
                endpoint,
                ..
            } => (streaming, endpoint.as_str()),
        };
        let url = format!("{}{}", endpoint.trim_end_matches('/'), path);
        let response = fill(
            self.authorized("POST", &url, streaming.post(&url))?
                .header("Accept", "text/event-stream"),
        )
        .send()
        .await
        .map_err(|e| connection_error(&e))?;
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let body: serde_json::Value = response.json().await.unwrap_or_default();
        Err(match crate::error::ApiError::from_body(&body) {
            Some(err) => SdkError::Api(err),
            None => SdkError::RpcError(format!("HTTP {}", status)),
        })
    }

    /// Calls a JSON-RPC method with the given parameters.
    pub async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> SdkResult<T> {
        let id = self.request_id.fetch_add(1, Ordering::Relaxed);

        let request = RpcRequest {
            jsonrpc: "2.0",
            method,
            params,
            id,
        };

        tracing::debug!("RPC call: {} (id={})", method, id);

        let response_value: serde_json::Value = match &self.backend {
            RpcBackend::Http {
                http,
                endpoint,
                failover,
                ..
            } => {
                let mut result = dispatch_http(
                    self.authorized("POST", endpoint, http.post(endpoint))?,
                    &request,
                )
                .await;
                for next in failover.iter() {
                    if !matches!(
                        result,
                        Err(SdkError::Timeout | SdkError::ConnectionError(_))
                    ) {
                        break;
                    }
                    tracing::debug!("RPC call {} moves to {}", method, next);
                    result =
                        dispatch_http(self.authorized("POST", next, http.post(next))?, &request)
                            .await;
                }
                result?
            }
        };

        decode_response(response_value)
    }

    /// Calls `method` proving possession of `prover`'s key with a DPoP proof
    /// and no access token, as a token endpoint is called
    /// (`tenzro_refreshToken`).
    pub async fn call_with_proof<T: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
        prover: &dyn crate::access::DpopProver,
    ) -> SdkResult<T> {
        let id = self.request_id.fetch_add(1, Ordering::Relaxed);
        let request = RpcRequest {
            jsonrpc: "2.0",
            method,
            params,
            id,
        };
        let RpcBackend::Http { http, endpoint, .. } = &self.backend;
        let response_value = dispatch_http(
            proved_only(http.post(endpoint), endpoint, prover)?,
            &request,
        )
        .await?;
        decode_response(response_value)
    }

    /// Makes an HTTP GET request to the Web API (non-RPC).
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> SdkResult<T> {
        let (http, endpoint) = self.require_http()?;
        let url = web_api_url(endpoint, path);
        let response = self
            .authorized("GET", &url, http.get(&url))?
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    SdkError::Timeout
                } else {
                    connection_error(&e)
                }
            })?;

        if !response.status().is_success() {
            return Err(SdkError::RpcError(format!(
                "HTTP {}: {}",
                response.status(),
                response.status().canonical_reason().unwrap_or("Unknown")
            )));
        }

        response
            .json()
            .await
            .map_err(|e| SdkError::RpcError(format!("Failed to parse response: {}", e)))
    }

    /// Makes an HTTP POST request to the Web API (non-RPC). HTTP-only;
    /// see [`Self::get`].
    pub async fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> SdkResult<T> {
        let (http, endpoint) = self.require_http()?;
        let url = web_api_url(endpoint, path);
        let response = self
            .authorized("POST", &url, http.post(&url))?
            .json(body)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    SdkError::Timeout
                } else {
                    connection_error(&e)
                }
            })?;

        if !response.status().is_success() {
            return Err(SdkError::RpcError(format!(
                "HTTP {}: {}",
                response.status(),
                response.status().canonical_reason().unwrap_or("Unknown")
            )));
        }

        response
            .json()
            .await
            .map_err(|e| SdkError::RpcError(format!("Failed to parse response: {}", e)))
    }

    /// Calls an A2A v1.0 JSON-RPC method on the node's `/a2a` endpoint.
    ///
    /// Sends the `A2A-Version: 1.0` header the protocol requires on every
    /// request and unwraps the JSON-RPC envelope: a JSON-RPC `error` becomes
    /// an [`SdkError::RpcError`], a `result` is deserialized into `T`.
    /// HTTP-only.
    pub async fn a2a_call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> SdkResult<T> {
        let (http, endpoint) = self.require_http()?;
        let url = web_api_url(endpoint, "/a2a");
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let response = self
            .authorized("POST", &url, http.post(&url))?
            .header(A2A_VERSION_HEADER, A2A_PROTOCOL_VERSION)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    SdkError::Timeout
                } else {
                    connection_error(&e)
                }
            })?;
        if !response.status().is_success() {
            return Err(SdkError::RpcError(format!(
                "HTTP {}: {}",
                response.status(),
                response.status().canonical_reason().unwrap_or("Unknown")
            )));
        }
        let envelope: serde_json::Value = response
            .json()
            .await
            .map_err(|e| SdkError::RpcError(format!("Failed to parse response: {}", e)))?;
        decode_a2a_envelope(envelope)
    }

    /// Makes an authenticated HTTP POST to the Web API with caller-supplied
    /// DPoP-bound JWT and DPoP proof headers (RFC 9449).
    ///
    /// Unlike the JSON-RPC `call()` path, web-API endpoints in the
    /// `/wallet/*` family require a fresh DPoP proof per request that
    /// signs over the exact `(method, htu)` pair. Because the caller
    /// (wallet kernel) is the only party who can produce that proof,
    /// the SDK cannot infer it from environment ambient state — it
    /// must be passed in. HTTP-only.
    pub async fn post_with_auth<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        bearer_jwt: &str,
        dpop_proof: &str,
    ) -> SdkResult<T> {
        let (http, endpoint) = self.require_http()?;
        let url = web_api_url(endpoint, path);
        let response = self
            .authorized("POST", &url, http.post(&url))?
            .header("Authorization", format!("DPoP {}", bearer_jwt))
            .header("DPoP", dpop_proof)
            .json(body)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    SdkError::Timeout
                } else {
                    connection_error(&e)
                }
            })?;

        if !response.status().is_success() {
            return Err(SdkError::RpcError(format!(
                "HTTP {}: {}",
                response.status(),
                response.status().canonical_reason().unwrap_or("Unknown")
            )));
        }
        response
            .json()
            .await
            .map_err(|e| SdkError::RpcError(format!("Failed to parse response: {}", e)))
    }

    /// Authenticated counterpart to [`Self::get`] — see
    /// [`Self::post_with_auth`] for the rationale. HTTP-only.
    pub async fn get_with_auth<T: DeserializeOwned>(
        &self,
        path: &str,
        bearer_jwt: &str,
        dpop_proof: &str,
    ) -> SdkResult<T> {
        let (http, endpoint) = self.require_http()?;
        let url = web_api_url(endpoint, path);
        let response = self
            .authorized("GET", &url, http.get(&url))?
            .header("Authorization", format!("DPoP {}", bearer_jwt))
            .header("DPoP", dpop_proof)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    SdkError::Timeout
                } else {
                    connection_error(&e)
                }
            })?;

        if !response.status().is_success() {
            return Err(SdkError::RpcError(format!(
                "HTTP {}: {}",
                response.status(),
                response.status().canonical_reason().unwrap_or("Unknown")
            )));
        }
        response
            .json()
            .await
            .map_err(|e| SdkError::RpcError(format!("Failed to parse response: {}", e)))
    }

    /// Build the Web API base URL by mapping the configured RPC
    /// endpoint to its sibling Web API host. HTTP-only.
    pub fn web_api_url(&self, path: &str) -> SdkResult<String> {
        let (_http, endpoint) = self.require_http()?;
        Ok(web_api_url(endpoint, path))
    }

    /// Returns the RPC endpoint URL.
    pub fn endpoint(&self) -> Option<&str> {
        match &self.backend {
            RpcBackend::Http { endpoint, .. } => Some(endpoint),
        }
    }

    /// The HTTP client and endpoint.
    fn require_http(&self) -> SdkResult<(&reqwest::Client, &str)> {
        match &self.backend {
            RpcBackend::Http { http, endpoint, .. } => Ok((http, endpoint.as_str())),
        }
    }
}

/// Header carrying the A2A protocol version on every A2A request.
pub const A2A_VERSION_HEADER: &str = "A2A-Version";
/// A2A protocol version this SDK speaks (`Major.Minor`).
pub const A2A_PROTOCOL_VERSION: &str = "1.0";
/// Well-known path of a public A2A agent card.
pub const A2A_AGENT_CARD_PATH: &str = "/.well-known/agent-card.json";

/// Unwrap an A2A JSON-RPC response envelope into its `result`.
fn decode_a2a_envelope<T: DeserializeOwned>(envelope: serde_json::Value) -> SdkResult<T> {
    if let Some(err) = envelope.get("error").filter(|e| !e.is_null()) {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
        let message = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("A2A error");
        return Err(SdkError::RpcError(format!(
            "A2A error {}: {}",
            code, message
        )));
    }
    let result = envelope
        .get("result")
        .cloned()
        .ok_or_else(|| SdkError::RpcError("A2A response carries no result".to_string()))?;
    serde_json::from_value(result)
        .map_err(|e| SdkError::RpcError(format!("Failed to parse A2A result: {}", e)))
}

/// The Web API base URL of a node: its JSON-RPC endpoint, except that a
/// local node serves the Web API on `:8080` beside JSON-RPC on `:8545`.
fn web_api_url(endpoint: &str, path: &str) -> String {
    let base = endpoint.trim_end_matches('/');
    if base.contains("localhost:8545") || base.contains("127.0.0.1:8545") {
        format!("{}{}", base.replace("8545", "8080"), path)
    } else {
        format!("{}{}", base, path)
    }
}

/// HTTP backend JSON-RPC dispatch over a POST that already carries the
/// client's access token and DPoP proof.
async fn dispatch_http(
    req: reqwest::RequestBuilder,
    request: &RpcRequest<'_>,
) -> SdkResult<serde_json::Value> {
    let req = req.json(request);

    let response = req.send().await.map_err(|e| {
        if e.is_timeout() {
            SdkError::Timeout
        } else {
            connection_error(&e)
        }
    })?;

    if !response.status().is_success() {
        return Err(SdkError::RpcError(format!(
            "HTTP {}: {}",
            response.status(),
            response.status().canonical_reason().unwrap_or("Unknown")
        )));
    }

    response
        .json::<serde_json::Value>()
        .await
        .map_err(|e| SdkError::RpcError(format!("Failed to parse response: {}", e)))
}

/// An environment variable's value, when set and not empty.
fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "agents")]
    use crate::agent::{A2aSendMessageResponse, a2a_text_message};

    #[test]
    #[cfg(feature = "agents")]
    fn a2a_send_message_params_use_v1_shapes() {
        let params = a2a_text_message("summarise the report");
        let msg = &params["message"];
        assert_eq!(msg["role"], "ROLE_USER");
        assert_eq!(msg["parts"][0]["text"], "summarise the report");
        assert!(msg["parts"][0].get("type").is_none());
        assert!(msg["parts"][0].get("kind").is_none());
        assert!(!msg["messageId"].as_str().unwrap().is_empty());
    }

    #[test]
    #[cfg(feature = "agents")]
    fn a2a_envelope_result_decodes_task() {
        let envelope = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "task": {
                    "id": "t-1",
                    "contextId": "c-1",
                    "status": { "state": "TASK_STATE_COMPLETED" },
                }
            }
        });
        let decoded: A2aSendMessageResponse = decode_a2a_envelope(envelope).unwrap();
        let task = decoded.task.unwrap();
        assert_eq!(task.id, "t-1");
        assert_eq!(task.context_id.as_deref(), Some("c-1"));
        assert_eq!(task.status.state, "TASK_STATE_COMPLETED");
        assert!(decoded.message.is_none());
    }

    #[test]
    fn a_null_result_is_a_result() {
        let none: Option<u64> =
            decode_response(serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": null }))
                .unwrap();
        assert_eq!(none, None);
        let value: serde_json::Value =
            decode_response(serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": null }))
                .unwrap();
        assert!(value.is_null());
        let some: Option<u64> =
            decode_response(serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": 7 })).unwrap();
        assert_eq!(some, Some(7));
    }

    #[test]
    fn a_response_without_result_or_error_is_malformed() {
        let err =
            decode_response::<serde_json::Value>(serde_json::json!({ "jsonrpc": "2.0", "id": 1 }))
                .unwrap_err();
        assert!(matches!(err, SdkError::RpcError(m) if m.contains("missing result")));
        let err = decode_response::<u64>(
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": null }),
        )
        .unwrap_err();
        assert!(matches!(err, SdkError::RpcError(_)));
    }

    #[test]
    fn an_error_wins_over_a_result_and_keeps_its_data() {
        let err = decode_response::<serde_json::Value>(serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "error": { "code": -32004, "message": "light", "data": { "build": "light" } }
        }))
        .unwrap_err();
        assert!(err.node_error().unwrap().is_light_build());
    }

    #[test]
    fn a2a_envelope_error_is_an_error() {
        let envelope = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": { "code": -32009, "message": "version not supported" }
        });
        let err = decode_a2a_envelope::<serde_json::Value>(envelope).unwrap_err();
        assert!(err.to_string().contains("-32009"));
    }

    /// A prover that names the request it proves, so the test can see it.
    struct EchoProver;

    impl crate::access::DpopProver for EchoProver {
        fn jkt(&self) -> SdkResult<String> {
            Ok("jkt".to_string())
        }
        fn proof(&self, htm: &str, htu: &str, access_token: &str) -> SdkResult<String> {
            Ok(format!("{htm} {htu} {access_token}"))
        }
    }

    fn signed_in(token: &str) -> RpcClient {
        let credential = AccessCredential {
            token: token.to_string(),
            prover: Arc::new(EchoProver),
        };
        RpcClient::new(
            "http://node.invalid",
            Duration::from_secs(1),
            Some(credential),
        )
        .unwrap()
    }

    #[test]
    fn every_request_carries_the_clients_own_token_and_a_proof_for_it() {
        let http = reqwest::Client::new();
        for (client, token) in [(signed_in("tok_a"), "tok_a"), (signed_in("tok_b"), "tok_b")] {
            for (htm, url) in [
                ("POST", "http://node.invalid/"),
                ("GET", "http://node.invalid/a2a"),
            ] {
                let req = client
                    .authorized(htm, url, http.request(htm.parse().unwrap(), url))
                    .unwrap()
                    .build()
                    .unwrap();
                assert_eq!(req.headers()["Authorization"], format!("DPoP {token}"));
                assert_eq!(req.headers()["DPoP"], format!("{htm} {url} {token}"));
            }
        }
    }

    #[test]
    fn a_token_endpoint_call_proves_its_key_and_presents_no_token() {
        let http = reqwest::Client::new();
        let url = "http://node.invalid/";
        let req = proved_only(http.post(url), url, &EchoProver)
            .unwrap()
            .build()
            .unwrap();
        assert!(req.headers().get("Authorization").is_none());
        assert_eq!(req.headers()["DPoP"], format!("POST {url} "));
    }

    #[test]
    fn a2a_constants_match_the_protocol() {
        assert_eq!(A2A_VERSION_HEADER, "A2A-Version");
        assert_eq!(A2A_PROTOCOL_VERSION, "1.0");
        assert_eq!(A2A_AGENT_CARD_PATH, "/.well-known/agent-card.json");
    }
}
