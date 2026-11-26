//! JSON-RPC client for communicating with Tenzro nodes

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// RPC client for Tenzro node communication
pub struct RpcClient {
    http: reqwest::Client,
    rpc_url: String,
    api_url: String,
    request_id: std::sync::atomic::AtomicU64,
}

#[derive(Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'a str,
    method: &'a str,
    params: Value,
    id: u64,
}

#[derive(Deserialize)]
struct JsonRpcResponse {
    #[serde(default)]
    result: Value,
    error: Option<JsonRpcError>,
}

/// Decodes a successful call's `result`. A `null` result is an answer (a
/// lookup that found nothing), so it decodes into any type that has a null
/// form (`Value`, `Option<_>`, `()`); only a type that needs a value fails.
fn decode_result<T: serde::de::DeserializeOwned>(method: &str, result: Value) -> Result<T> {
    let was_null = result.is_null();
    serde_json::from_value(result).map_err(|e| {
        if was_null {
            anyhow::anyhow!("{method} returned no result")
        } else {
            anyhow::anyhow!("{method} returned an unexpected result: {e}")
        }
    })
}

#[derive(Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
    /// Structured payload the node attaches to some rejections.
    ///
    /// The mempool fee-floor rejection (`-32012`) carries the gas price it
    /// actually requires here, which is the only way a client can resubmit
    /// correctly without hardcoding a floor that drifts out of date.
    #[serde(default)]
    data: Option<Value>,
}

/// JSON-RPC error code the node returns when a transaction's `gas_price` is
/// below the mempool lane's fee floor. Its `data.required` names the floor.
pub const RPC_ERR_FEE_FLOOR: i64 = -32012;

/// JSON-RPC error code the node returns while it cannot take a request yet:
/// a served model that is still loading (`data.status` is `"warming"`) or a
/// request refused for load.
pub const RPC_ERR_BUSY: i64 = -32005;

/// A served model the node is still loading, for example after it was
/// unloaded for being idle.
#[derive(Debug, PartialEq, Eq)]
pub struct ModelLoading {
    pub model: String,
    /// The node's estimate of when the model is ready.
    pub ready_ms: u64,
}

impl std::fmt::Display for ModelLoading {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the model {} is loading; ask again in about {} s",
            self.model,
            self.ready_ms.div_ceil(1000).max(1)
        )
    }
}

impl std::error::Error for ModelLoading {}

impl ModelLoading {
    fn of(err: &JsonRpcError) -> Option<Self> {
        let data = err.data.as_ref()?;
        (err.code == RPC_ERR_BUSY && data["status"] == "warming").then(|| Self {
            model: data["model"].as_str().unwrap_or_default().to_string(),
            ready_ms: data["estimated_ready_ms"].as_u64().unwrap_or_default(),
        })
    }
}

impl RpcClient {
    /// Create a new RPC client
    pub fn new(rpc_url: &str) -> Self {
        // A command that left its flag at the local default takes the
        // endpoint chosen for the process (--rpc, TENZRO_RPC, or the one
        // `tenzro setup` saved).
        Self::at(&crate::endpoint::for_command(rpc_url))
    }

    /// A client for the node at exactly `rpc_url`, whatever endpoint the
    /// process was given.
    pub fn at(rpc_url: &str) -> Self {
        // Derive API URL from RPC URL
        // localhost:8545 → localhost:8080
        // localhost:9944 → localhost:8080
        // rpc.tenzro.com → api.tenzro.com
        // Derive Web API URL from RPC URL:
        // - localhost:8545 → localhost:8080
        // - localhost:18545 → localhost:18080 (test ports: subtract 465)
        // - rpc.tenzro.com → api.tenzro.com
        let api_url = if rpc_url.contains("localhost") || rpc_url.contains("127.0.0.1") {
            // Try to extract port and map to API port
            if let Some(port_start) = rpc_url.rfind(':') {
                let port_str = &rpc_url[port_start + 1..];
                let port_str = port_str.trim_end_matches('/');
                if let Ok(port) = port_str.parse::<u16>() {
                    // Map RPC port to API port: 8545→8080, 18545→18080, etc.
                    let api_port = if port == 8545 || port == 9944 {
                        8080
                    } else {
                        // For custom ports, try replacing last 3 digits: *545 → *080
                        let base = port / 1000 * 1000;
                        if port % 1000 == 545 {
                            base + 80
                        } else {
                            port.saturating_sub(465) // fallback: 8545-8080=465
                        }
                    };
                    format!("{}:{}", &rpc_url[..port_start], api_port)
                } else {
                    rpc_url.replace(":8545", ":8080").replace(":9944", ":8080")
                }
            } else {
                rpc_url.to_string()
            }
        } else {
            rpc_url.replace("rpc.", "api.")
        };

        Self {
            http: Self::http(reqwest::redirect::Policy::default()),
            rpc_url: rpc_url.to_string(),
            api_url,
            request_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// A client for the node at exactly `rpc_url` that follows no redirect,
    /// so what it carries, a signed-in session among it, reaches no other
    /// origin.
    pub fn only_at(rpc_url: &str) -> Self {
        Self {
            http: Self::http(reqwest::redirect::Policy::none()),
            ..Self::at(rpc_url)
        }
    }

    fn http(redirect: reqwest::redirect::Policy) -> reqwest::Client {
        // The node records the client of every administrative call.
        reqwest::Client::builder()
            .user_agent(concat!("tenzro-cli/", env!("CARGO_PKG_VERSION")))
            .redirect(redirect)
            .build()
            .unwrap_or_default()
    }

    /// Get the RPC URL
    pub fn url(&self) -> &str {
        &self.rpc_url
    }

    /// Longest answer [`forward`](Self::forward) reads: the reads it passes
    /// on answer in kilobytes, and a node or remote target that streams more
    /// is refused rather than buffered.
    const FORWARD_BODY_LIMIT: usize = 4 << 20;

    /// Sends `method` to the node and returns what it answered: its result, or
    /// its error object exactly as it sent it. `Err` means no answer came, or
    /// one longer than [`FORWARD_BODY_LIMIT`](Self::FORWARD_BODY_LIMIT).
    pub async fn forward(
        &self,
        method: &str,
        params: Value,
    ) -> Result<std::result::Result<Value, Value>> {
        let id = self
            .request_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            method,
            params,
            id,
        };
        let mut response = self
            .authorized(self.http.post(&self.rpc_url).json(&request), &self.rpc_url)
            .send()
            .await
            .map_err(|e| crate::friendly::from_reqwest(&self.rpc_url, e))?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if bytes.len() + chunk.len() > Self::FORWARD_BODY_LIMIT {
                anyhow::bail!("{method}: the node's answer is longer than the helper reads");
            }
            bytes.extend_from_slice(&chunk);
        }
        let mut body: Value = serde_json::from_slice(&bytes)?;
        Ok(match body.get_mut("error").map(Value::take) {
            Some(error) if !error.is_null() => Err(error),
            _ => Ok(body
                .get_mut("result")
                .map(Value::take)
                .unwrap_or(Value::Null)),
        })
    }

    /// Make a JSON-RPC call.
    ///
    /// Forwards `Authorization: DPoP <jwt>` and a fresh `DPoP` proof when an
    /// access token is at hand: `TENZRO_BEARER_JWT`, or the one
    /// `tenzro access sign-in` stored. Whether a method needs one is the
    /// node's access policy.
    pub async fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> Result<T> {
        let id = self
            .request_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            method,
            params,
            id,
        };

        let req = self.authorized(self.http.post(&self.rpc_url).json(&request), &self.rpc_url);

        let response = req
            .send()
            .await
            .map_err(|e| crate::friendly::from_reqwest(&self.rpc_url, e))?;

        let body: JsonRpcResponse = response.json().await?;

        if let Some(err) = body.error {
            // Surface the required floor in a form the caller can act on, so a
            // fee-floor rejection is recoverable rather than terminal.
            if err.code == RPC_ERR_FEE_FLOOR
                && let Some(required) = err
                    .data
                    .as_ref()
                    .and_then(|d| d.get("required"))
                    .and_then(json_u128)
            {
                anyhow::bail!(
                    "RPC error [{}]: {} (required_gas_price={})",
                    err.code,
                    err.message,
                    required
                );
            }
            if let Some(loading) = ModelLoading::of(&err) {
                return Err(loading.into());
            }
            // Whatever else the node attached (a custody signing request, a
            // refused field) stays with the error rather than being dropped.
            match err.data.filter(|d| !d.is_null()) {
                Some(data) => {
                    anyhow::bail!("RPC error [{}]: {} (data: {})", err.code, err.message, data)
                }
                None => anyhow::bail!("RPC error [{}]: {}", err.code, err.message),
            }
        }

        decode_result(method, body.result)
    }

    /// Make a JSON-RPC call proving possession of this machine's DPoP key with
    /// a proof that accompanies no access token, as a token endpoint is
    /// called (`tenzro_refreshToken`).
    pub async fn call_with_proof<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> Result<T> {
        let id = self
            .request_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            method,
            params,
            id,
        };
        let proof = crate::dpop::load_or_create()?.proof("POST", &self.rpc_url, None)?;
        let response = self
            .http
            .post(&self.rpc_url)
            .header("DPoP", proof)
            .json(&request)
            .send()
            .await
            .map_err(|e| crate::friendly::from_reqwest(&self.rpc_url, e))?;
        let body: JsonRpcResponse = response.json().await?;
        if let Some(err) = body.error {
            anyhow::bail!("RPC error [{}]: {}", err.code, err.message);
        }
        decode_result(method, body.result)
    }

    /// Send a signed transaction, resubmitting once at the node's required
    /// gas price if the first attempt is below the mempool fee floor.
    ///
    /// Every transaction-submitting command used to hardcode
    /// `gas_price: 1_000_000_000` (1 gwei). The deployed open lane requires
    /// `4×` that, so `tenzro join --provider` could not post its compute bond
    /// at all: the node rejected it with `Fee floor not met for open lane:
    /// gas_price 1000000000 < required 4000000000`, and the operator had to
    /// hand-sign a replacement. Hardcoding `4_000_000_000` instead would only
    /// move the cliff — the floor is a deployment setting and moves with the
    /// fee market.
    ///
    /// The node already reports the exact figure it wants in `data.required`,
    /// so ask, then comply. One retry only: a second rejection means something
    /// other than the floor is wrong, and looping would just spend the
    /// operator's nonce.
    pub async fn send_tx_clearing_fee_floor(
        &self,
        method: &str,
        mut params: Value,
    ) -> Result<Value> {
        match self.call::<Value>(method, params.clone()).await {
            Ok(v) => Ok(v),
            Err(e) => {
                let Some(required) = parse_required_gas_price(&e.to_string()) else {
                    return Err(e);
                };
                if let Some(map) = params.as_object_mut() {
                    map.insert("gas_price".to_string(), Value::from(required));
                }
                self.call::<Value>(method, params).await
            }
        }
    }

    /// `req` with the caller's bearer and a fresh DPoP proof bound to it for
    /// a POST to `url`, when this machine holds both.
    fn authorized(&self, req: reqwest::RequestBuilder, url: &str) -> reqwest::RequestBuilder {
        // Resolve the bearer: the env var wins (override / debugging), otherwise
        // fall back to the session token persisted by `tenzro auth`, so
        // privileged commands work after login without manually exporting
        // TENZRO_BEARER_JWT.
        let Some(bearer) = session_token_for(&self.rpc_url) else {
            return req;
        };
        // A DPoP proof is per-request: it commits to this method and URL,
        // carries a `jti` the node caches against replay, and is valid for
        // ±60s. So it is minted here rather than exported — an env var can
        // only ever carry one that works once.
        //
        // `TENZRO_DPOP_PROOF` still wins when set, for debugging and for
        // callers holding their key somewhere this process cannot reach.
        let override_proof = std::env::var("TENZRO_DPOP_PROOF")
            .ok()
            .filter(|p| !p.is_empty());
        let mint = |token: &str| -> Result<(String, String)> {
            if !crate::dpop::exists() {
                anyhow::bail!("this machine holds no DPoP key");
            }
            let key = crate::dpop::load_or_create()?;
            Ok((key.proof("POST", url, Some(token))?, key.jkt()?))
        };
        match bound_credentials(bearer, override_proof, mint) {
            Ok((token, proof)) => req
                .header("Authorization", format!("DPoP {token}"))
                .header("DPoP", proof),
            Err(reason) => {
                static WARNED: std::sync::Once = std::sync::Once::new();
                WARNED.call_once(|| {
                    eprintln!(
                        "warning: the access token was not sent ({reason}); \
                     run `tenzro access sign-in` again for methods that need it"
                    )
                });
                req
            }
        }
    }

    /// POST `body` to a route on the node's RPC listener and hand back the
    /// response as it arrives (a server-sent event stream for realtime routes).
    pub async fn post_route(&self, path: &str, body: Vec<u8>) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.rpc_url.trim_end_matches('/'), path);
        let req = self.authorized(self.http.post(&url).body(body), &url);
        let response = req
            .send()
            .await
            .map_err(|e| crate::friendly::from_reqwest(&self.rpc_url, e))?;
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("{path}: {status}: {text}"));
        }
        Ok(response)
    }

    pub async fn api_get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", self.api_url, path);
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| crate::friendly::from_reqwest(&self.api_url, e))?;
        let body: T = response.json().await?;
        Ok(body)
    }

    /// Make a POST request to the Web API
    pub async fn api_post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<T> {
        let url = format!("{}{}", self.api_url, path);
        let response = self
            .http
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(|e| crate::friendly::from_reqwest(&self.api_url, e))?;
        let result: T = response.json().await?;
        Ok(result)
    }
}

/// Parse a hex string (with or without 0x prefix) to u128
pub fn parse_hex_u128(hex: &str) -> u128 {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    u128::from_str_radix(hex, 16).unwrap_or(0)
}

/// Fetch `(nonce, chain_id)` for `address`, the pair every native typed
/// transaction needs before it can be signed.
///
/// A value passed in `nonce` or `chain_id` is used as given and not read.
/// Anything read must be answered: a transaction is signed over its chain id
/// and nonce, so a guessed value signs for another network or replays a used
/// nonce. A node that cannot answer is an error naming the endpoint, never a
/// default. A fresh account's nonce is read as `0x0` like any other.
pub async fn fetch_nonce_and_chain_id(
    rpc: &RpcClient,
    address: &str,
    nonce: Option<u64>,
    chain_id: Option<u64>,
) -> Result<(u64, u64)> {
    let nonce = match nonce {
        Some(n) => n,
        None => fetch_nonce(rpc, address).await?,
    };
    let chain_id = match chain_id {
        Some(c) => c,
        None => fetch_chain_id(rpc).await?,
    };
    Ok((nonce, chain_id))
}

/// The next nonce of `address`, counting its pending transactions, read
/// from the node at `rpc`. No fallback: see [`fetch_nonce_and_chain_id`].
pub async fn fetch_nonce(rpc: &RpcClient, address: &str) -> Result<u64> {
    let v: Value = rpc
        .call(
            "eth_getTransactionCount",
            serde_json::json!([address, "pending"]),
        )
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "could not read the nonce of {address} from {}: {e}",
                rpc.url()
            )
        })?;
    strict_hex_u64(&v).ok_or_else(|| {
        anyhow::anyhow!(
            "eth_getTransactionCount at {} returned {v}, not a nonce",
            rpc.url()
        )
    })
}

/// A JSON-RPC quantity (`"0x..."`) as a u64, or `None` for anything else.
fn strict_hex_u64(v: &Value) -> Option<u64> {
    let digits = v.as_str()?.strip_prefix("0x")?;
    if digits.is_empty() {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

/// The gas price the node admits and executes a transaction at now. A
/// transaction is signed over its gas price, so it is asked for before
/// signing rather than corrected after a refusal.
pub async fn fetch_gas_price(rpc: &RpcClient) -> Result<u64> {
    let v: serde_json::Value = rpc.call("eth_gasPrice", serde_json::json!([])).await?;
    let hex = v
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("eth_gasPrice returned {v}"))?;
    u64::from_str_radix(hex.trim_start_matches("0x"), 16)
        .map_err(|e| anyhow::anyhow!("eth_gasPrice returned {hex}: {e}"))
}

/// The chain id the node at `rpc` runs. No fallback: anything signed for a
/// guessed chain id is refused on the real one, or accepted on the wrong one.
pub async fn fetch_chain_id(rpc: &RpcClient) -> Result<u64> {
    let chain_id: Value = rpc
        .call("eth_chainId", serde_json::json!([]))
        .await
        .map_err(|e| anyhow::anyhow!("could not read the chain id from {}: {e}", rpc.url()))?;
    strict_hex_u64(&chain_id).ok_or_else(|| {
        anyhow::anyhow!(
            "eth_chainId at {} returned {chain_id}, not a chain id",
            rpc.url()
        )
    })
}

/// Parse a hex string (with or without 0x prefix) to u64
pub fn parse_hex_u64(hex: &str) -> u64 {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    u64::from_str_radix(hex, 16).unwrap_or(0)
}

/// Format wei to TNZO (18 decimals)
pub fn format_tnzo(wei: u128) -> String {
    // Integer arithmetic: going through f64 turned 100000 TNZO (1e23 wei, not
    // representable) into "100000.000000 TNZO", which is the amount the RPC
    // operator and attestor roles need.
    const ONE: u128 = 1_000_000_000_000_000_000;
    if wei.is_multiple_of(ONE) {
        return format!("{} TNZO", wei / ONE);
    }
    // Six decimals, rounded to the nearest micro-TNZO.
    let micro = (wei + 500_000_000_000) / 1_000_000_000_000;
    format!("{}.{:06} TNZO", micro / 1_000_000, micro % 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(body: &str) -> JsonRpcResponse {
        serde_json::from_str(body).expect("a JSON-RPC response")
    }

    #[test]
    fn a_model_still_loading_is_told_apart_from_a_refusal() {
        let error = |body: &str| response(body).error.expect("an error");
        let loading = error(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32005,
                "message":"model 'm' is loading; retry in about 1500 ms",
                "data":{"status":"warming","model":"m","estimated_ready_ms":1500,
                        "retry_after_ms":500,"waiters":1}}}"#,
        );
        let said = ModelLoading::of(&loading).expect("a loading model");
        assert_eq!(
            said,
            ModelLoading {
                model: "m".into(),
                ready_ms: 1500
            }
        );
        assert_eq!(
            anyhow::Error::from(said).to_string(),
            "the model m is loading; ask again in about 2 s"
        );
        let refused = error(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"busy",
                "data":{"status":"refused","retry_after_ms":500}}}"#,
        );
        assert_eq!(ModelLoading::of(&refused), None);
    }

    #[test]
    fn format_tnzo_is_exact_for_large_whole_amounts() {
        let one = 1_000_000_000_000_000_000u128;
        assert_eq!(format_tnzo(100_000 * one), "100000 TNZO");
        assert_eq!(format_tnzo(5 * one / 2), "2.500000 TNZO");
        assert_eq!(format_tnzo(0), "0 TNZO");
    }

    #[test]
    fn a_null_result_is_an_answer_for_types_that_have_one() {
        // A lookup that finds nothing, e.g. an agent without a bond.
        let r = response(r#"{"jsonrpc":"2.0","id":1,"result":null}"#);
        assert!(r.error.is_none());
        let v: Value = decode_result("tenzro_getAgentBond", r.result.clone()).unwrap();
        assert!(v.is_null());
        let o: Option<Value> = decode_result("tenzro_getAgentBond", r.result).unwrap();
        assert!(o.is_none());
    }

    #[test]
    fn a_missing_result_decodes_like_null() {
        let r = response(r#"{"jsonrpc":"2.0","id":1}"#);
        let v: Value = decode_result("m", r.result).unwrap();
        assert!(v.is_null());
    }

    #[test]
    fn a_null_result_is_refused_where_a_value_is_needed() {
        let r = response(r#"{"jsonrpc":"2.0","id":1,"result":null}"#);
        let e = decode_result::<u64>("tenzro_blockNumber", r.result).unwrap_err();
        assert!(e.to_string().contains("returned no result"), "{e}");
    }

    #[test]
    fn a_present_result_decodes() {
        let r = response(r#"{"jsonrpc":"2.0","id":1,"result":{"amount":"5"}}"#);
        let v: Value = decode_result("tenzro_getAgentBond", r.result).unwrap();
        assert_eq!(v["amount"], "5");
    }

    #[test]
    fn test_parse_hex_u128() {
        assert_eq!(parse_hex_u128("0x100"), 256);
        assert_eq!(parse_hex_u128("100"), 256);
        assert_eq!(parse_hex_u128("0x0"), 0);
    }

    #[test]
    fn test_parse_hex_u64() {
        assert_eq!(parse_hex_u64("0xFF"), 255);
        assert_eq!(parse_hex_u64("FF"), 255);
    }

    #[test]
    fn test_format_tnzo() {
        assert_eq!(format_tnzo(1_000_000_000_000_000_000), "1 TNZO");
        assert_eq!(format_tnzo(1_500_000_000_000_000_000), "1.500000 TNZO");
    }

    #[test]
    fn test_rpc_client_creation() {
        let client = RpcClient::new("http://localhost:8545");
        assert_eq!(client.rpc_url, "http://localhost:8545");
        assert_eq!(client.api_url, "http://localhost:8080");

        let client2 = RpcClient::new("https://rpc.tenzro.com");
        assert_eq!(client2.api_url, "https://api.tenzro.com");
    }
}

/// Read a JSON number-or-string as `u128`.
///
/// JSON has no native u128, so the node sends large integers as decimal
/// strings and small ones as numbers; accept both.
fn json_u128(v: &Value) -> Option<u128> {
    if let Some(s) = v.as_str() {
        return s.parse::<u128>().ok();
    }
    v.as_u64().map(u128::from)
}

/// Pull `required_gas_price=N` back out of a fee-floor error string.
///
/// `call` formats the structured `data.required` into its message so the
/// figure survives the crossing into `anyhow::Error`, which erases types.
fn parse_required_gas_price(msg: &str) -> Option<u64> {
    let tail = msg.split("required_gas_price=").nth(1)?;
    let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse::<u64>().ok()
}

#[cfg(test)]
mod fee_floor_tests {
    use super::*;

    #[test]
    fn the_required_gas_price_survives_the_error_string() {
        let msg = "RPC error [-32012]: Fee floor not met for open lane: \
                   gas_price 1000000000 < required 4000000000 (4.00× base 1000000000) \
                   (required_gas_price=4000000000)";
        assert_eq!(parse_required_gas_price(msg), Some(4_000_000_000));
    }

    #[test]
    fn an_unrelated_error_yields_no_retry_price() {
        assert_eq!(
            parse_required_gas_price("RPC error [-32602]: Invalid address: 3F5Yu"),
            None
        );
    }

    #[test]
    fn json_u128_takes_both_encodings() {
        assert_eq!(
            json_u128(&Value::from(4_000_000_000u64)),
            Some(4_000_000_000)
        );
        assert_eq!(
            json_u128(&Value::from("1000000000000000000000")),
            Some(10u128.pow(21))
        );
    }
}

/// The bearer this client holds: `TENZRO_BEARER_JWT` when set (override,
/// debugging), else the session token `tenzro auth` / `access sign-in`
/// persisted, while it is live.
pub fn session_token() -> Option<String> {
    bearer(None)
}

/// The bearer this client presents to `rpc_url`: as [`session_token`], and a
/// persisted token only to the endpoint that issued it.
pub fn session_token_for(rpc_url: &str) -> Option<String> {
    bearer(Some(rpc_url))
}

fn bearer(rpc_url: Option<&str>) -> Option<String> {
    std::env::var("TENZRO_BEARER_JWT")
        .ok()
        .filter(|t| !t.is_empty())
        .or_else(|| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            persisted_token(&crate::config::load_config(), rpc_url, now)
        })
}

/// The access token and the DPoP proof bound to it, or why the token cannot
/// be presented. The node refuses a request whose token comes without a
/// valid proof, including calls that need no token, so a token that cannot
/// be proven is left off rather than sent alone. A proof from
/// `override_proof` is taken as given; otherwise `mint` signs one and
/// reports its key's thumbprint, which must be the one the token is bound to
/// (`cnf.jkt`).
fn bound_credentials(
    token: String,
    override_proof: Option<String>,
    mint: impl FnOnce(&str) -> Result<(String, String)>,
) -> std::result::Result<(String, String), String> {
    if let Some(proof) = override_proof {
        return Ok((token, proof));
    }
    let (proof, jkt) = mint(&token).map_err(|e| format!("no DPoP proof: {e}"))?;
    match token_jkt(&token) {
        Some(bound) if bound == jkt => Ok((token, proof)),
        Some(_) => Err("it is bound to a different DPoP key than this machine's".into()),
        None => Err("it names no DPoP key".into()),
    }
}

/// The `cnf.jkt` claim of a JWT, read without checking its signature: the
/// node checks the token, this only decides whether to present it.
fn token_jkt(token: &str) -> Option<String> {
    use base64::Engine as _;
    let mut parts = token.split('.');
    let (Some(_), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("cnf")?.get("jkt")?.as_str().map(str::to_string)
}

#[cfg(test)]
mod bound_credentials_tests {
    use super::{bound_credentials, token_jkt};
    use base64::Engine as _;

    fn token_bound_to(jkt: &str) -> String {
        let enc = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);
        format!(
            "{}.{}.sig",
            enc(r#"{"alg":"ES256"}"#),
            enc(&format!(r#"{{"sub":"did:x","cnf":{{"jkt":"{jkt}"}}}}"#))
        )
    }

    #[test]
    fn a_token_goes_out_with_a_proof_from_the_key_it_is_bound_to() {
        let t = token_bound_to("K1");
        assert_eq!(token_jkt(&t).as_deref(), Some("K1"));
        let got = bound_credentials(t.clone(), None, |_| Ok(("P".into(), "K1".into())));
        assert_eq!(got, Ok((t, "P".into())));
    }

    #[test]
    fn a_token_that_cannot_be_proven_is_not_sent() {
        let t = token_bound_to("K1");
        assert!(bound_credentials(t.clone(), None, |_| anyhow::bail!("no key")).is_err());
        assert!(bound_credentials(t, None, |_| Ok(("P".into(), "K2".into()))).is_err());
        assert!(
            bound_credentials("opaque".into(), None, |_| Ok(("P".into(), "K1".into()))).is_err()
        );
    }

    #[test]
    fn a_proof_given_in_the_environment_is_used_as_given() {
        let got = bound_credentials("opaque".into(), Some("E".into()), |_| {
            panic!("no proof is minted when one is given")
        });
        assert_eq!(got, Ok(("opaque".into(), "E".into())));
    }
}

/// The persisted token, unless it has expired or another endpoint issued it.
/// Each node signs with its own key, so another node's token fails the
/// signature check and the node refuses the whole request, including calls
/// that need no token.
fn persisted_token(
    cfg: &crate::config::PersistedConfig,
    rpc_url: Option<&str>,
    now: u64,
) -> Option<String> {
    let token = cfg.access_token.as_ref().filter(|t| !t.is_empty())?;
    if cfg.access_token_expires_at.is_some_and(|exp| exp <= now) {
        return None;
    }
    if let (Some(url), Some(issuer)) = (rpc_url, cfg.access_token_rpc.as_deref())
        && url.trim_end_matches('/') != issuer.trim_end_matches('/')
    {
        return None;
    }
    Some(token.clone())
}

#[cfg(test)]
mod session_token_tests {
    use super::persisted_token;
    use crate::config::PersistedConfig;

    fn signed_in(rpc: Option<&str>, expires_at: Option<u64>) -> PersistedConfig {
        PersistedConfig {
            access_token: Some("t".into()),
            access_token_expires_at: expires_at,
            access_token_rpc: rpc.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn a_token_goes_only_to_the_endpoint_that_issued_it() {
        let cfg = signed_in(Some("http://127.0.0.1:29410"), Some(2_000));
        assert_eq!(
            persisted_token(&cfg, Some("http://127.0.0.1:29410/"), 1_000).as_deref(),
            Some("t")
        );
        assert_eq!(
            persisted_token(&cfg, Some("http://127.0.0.1:33600"), 1_000),
            None
        );
        assert_eq!(persisted_token(&cfg, None, 1_000).as_deref(), Some("t"));
    }

    #[test]
    fn an_expired_token_is_not_presented() {
        let cfg = signed_in(None, Some(1_000));
        assert_eq!(
            persisted_token(&cfg, Some("http://127.0.0.1:33600"), 1_000),
            None
        );
        assert_eq!(
            persisted_token(&cfg, Some("http://127.0.0.1:33600"), 999).as_deref(),
            Some("t")
        );
    }

    #[test]
    fn a_token_saved_before_its_endpoint_was_recorded_still_goes_out_while_live() {
        let cfg = signed_in(None, None);
        assert_eq!(
            persisted_token(&cfg, Some("http://127.0.0.1:8545"), 1_000).as_deref(),
            Some("t")
        );
    }
}

/// The nonce and chain id a transaction is signed over.
#[cfg(test)]
pub(crate) mod nonce_and_chain_id_tests {
    use super::*;

    /// A node at a loopback port that answers each JSON-RPC method from
    /// `answers`: an answer that starts with `{"code"` is sent as the error,
    /// any other as the result, and a method with no entry gets a JSON-RPC
    /// error. Returns the URL it serves.
    pub(crate) async fn node_answering(answers: &'static [(&'static str, &'static str)]) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    // Read the head, then as much body as it declares.
                    let body = loop {
                        let n = sock.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        let text = String::from_utf8_lossy(&buf).to_string();
                        if let Some(at) = text.find("\r\n\r\n") {
                            let len = text[..at]
                                .lines()
                                .find_map(|l| {
                                    let (k, v) = l.split_once(':')?;
                                    k.eq_ignore_ascii_case("content-length")
                                        .then(|| v.trim().parse::<usize>().ok())?
                                })
                                .unwrap_or(0);
                            if buf.len() >= at + 4 + len {
                                break buf[at + 4..at + 4 + len].to_vec();
                            }
                        }
                    };
                    let req: Value = serde_json::from_slice(&body).unwrap_or_default();
                    let method = req["method"].as_str().unwrap_or_default();
                    let reply = match answers.iter().find(|(m, _)| *m == method) {
                        Some((_, error)) if error.starts_with(r#"{"code""#) => {
                            format!(r#"{{"jsonrpc":"2.0","id":1,"error":{error}}}"#)
                        }
                        Some((_, result)) => {
                            format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#)
                        }
                        None => r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no such method"}}"#
                            .to_string(),
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                        reply.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        url
    }

    /// The URL of a loopback port nothing listens on.
    async fn closed_endpoint() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        url
    }

    const ACCOUNT: &str = "0x0101010101010101010101010101010101010101010101010101010101010101";

    #[tokio::test]
    async fn the_nonce_and_chain_id_are_read_from_the_node() {
        let url = node_answering(&[
            ("eth_chainId", r#""0x3444""#),
            ("eth_getTransactionCount", r#""0x7""#),
        ])
        .await;
        let rpc = RpcClient::new(&url);
        assert_eq!(
            fetch_nonce_and_chain_id(&rpc, ACCOUNT, None, None)
                .await
                .unwrap(),
            (7, 13380)
        );
        // A fresh account reads as nonce zero like any other.
        let url = node_answering(&[
            ("eth_chainId", r#""0x3444""#),
            ("eth_getTransactionCount", r#""0x0""#),
        ])
        .await;
        let rpc = RpcClient::new(&url);
        assert_eq!(
            fetch_nonce_and_chain_id(&rpc, ACCOUNT, None, None)
                .await
                .unwrap(),
            (0, 13380)
        );
    }

    #[tokio::test]
    async fn an_unreachable_node_is_an_error_naming_it_not_the_developer_chain() {
        // This used to answer (0, 1337): a transaction signed for the
        // developer chain, whatever network the caller meant.
        let url = closed_endpoint().await;
        let rpc = RpcClient::new(&url);
        let e = fetch_nonce_and_chain_id(&rpc, ACCOUNT, None, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains(&url), "the error must name the endpoint: {e}");
        let e = fetch_chain_id(&rpc).await.unwrap_err().to_string();
        assert!(e.contains(&url) && e.contains("chain id"), "{e}");
        let e = fetch_nonce(&rpc, ACCOUNT).await.unwrap_err().to_string();
        assert!(e.contains(&url) && e.contains("nonce"), "{e}");
    }

    #[tokio::test]
    async fn a_node_that_refuses_or_garbles_the_read_is_an_error() {
        // The chain id read is refused.
        let url = node_answering(&[("eth_getTransactionCount", r#""0x1""#)]).await;
        let rpc = RpcClient::new(&url);
        let e = fetch_nonce_and_chain_id(&rpc, ACCOUNT, None, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains(&url) && e.contains("chain id"), "{e}");
        // Answers that are not quantities, which a lenient parse reads as 0.
        for garbled in [r#"null"#, r#""1337""#, r#""0x""#, r#""0xzz""#, "5"] {
            let answers: &'static [(&'static str, &'static str)] = Box::leak(Box::new([
                ("eth_chainId", garbled),
                ("eth_getTransactionCount", garbled),
            ]));
            let url = node_answering(answers).await;
            let rpc = RpcClient::new(&url);
            let e = fetch_chain_id(&rpc).await.unwrap_err().to_string();
            assert!(e.contains(&url), "{garbled}: {e}");
            let e = fetch_nonce(&rpc, ACCOUNT).await.unwrap_err().to_string();
            assert!(e.contains(&url), "{garbled}: {e}");
        }
    }

    #[tokio::test]
    async fn an_explicit_nonce_or_chain_id_is_used_without_reading_it() {
        // Both given: the node is not asked at all.
        let rpc = RpcClient::new(&closed_endpoint().await);
        assert_eq!(
            fetch_nonce_and_chain_id(&rpc, ACCOUNT, Some(4), Some(13380))
                .await
                .unwrap(),
            (4, 13380)
        );
        // One given: only the other is read.
        let url = node_answering(&[("eth_getTransactionCount", r#""0x9""#)]).await;
        let rpc = RpcClient::new(&url);
        assert_eq!(
            fetch_nonce_and_chain_id(&rpc, ACCOUNT, None, Some(13380))
                .await
                .unwrap(),
            (9, 13380)
        );
        let url = node_answering(&[("eth_chainId", r#""0x539""#)]).await;
        let rpc = RpcClient::new(&url);
        assert_eq!(
            fetch_nonce_and_chain_id(&rpc, ACCOUNT, Some(2), None)
                .await
                .unwrap(),
            (2, 1337)
        );
    }

    #[tokio::test]
    async fn a_client_only_at_its_node_follows_no_redirect() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let elsewhere = node_answering(&[("tenzro_syncing", "false")]).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let _ = sock.read(&mut [0u8; 4096]).await;
                let moved = format!(
                    "HTTP/1.1 307 Temporary Redirect\r\nlocation: {elsewhere}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                );
                let _ = sock.write_all(moved.as_bytes()).await;
            }
        });
        // A client that follows is answered from the other origin.
        let followed = RpcClient::at(&url)
            .forward("tenzro_syncing", serde_json::json!([]))
            .await;
        assert_eq!(followed.unwrap(), Ok(serde_json::json!(false)));
        // One only at its node is not.
        let stayed = RpcClient::only_at(&url)
            .forward("tenzro_syncing", serde_json::json!([]))
            .await;
        assert!(
            stayed.is_err(),
            "answered from where it was sent: {stayed:?}"
        );
    }
}
