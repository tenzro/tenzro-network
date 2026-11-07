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

impl RpcClient {
    /// Create a new RPC client
    pub fn new(rpc_url: &str) -> Self {
        // A command that left its flag at the local default takes the
        // endpoint chosen for the process (--rpc, TENZRO_RPC, or the one
        // `tenzro setup` saved).
        let resolved = crate::endpoint::for_command(rpc_url);
        let rpc_url = resolved.as_str();
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

        // The node records the client of every administrative call.
        let http = reqwest::Client::builder()
            .user_agent(concat!("tenzro-cli/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_default();
        Self {
            http,
            rpc_url: rpc_url.to_string(),
            api_url,
            request_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Get the RPC URL
    pub fn url(&self) -> &str {
        &self.rpc_url
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
        let proof = crate::dpop::DpopKey::load_or_create()?.proof("POST", &self.rpc_url, None)?;
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

    /// Make a GET request to the Web API
    /// `req` with the caller's bearer and a fresh DPoP proof for a POST to
    /// `url`, when this machine holds them.
    fn authorized(&self, mut req: reqwest::RequestBuilder, url: &str) -> reqwest::RequestBuilder {
        // Resolve the bearer: the env var wins (override / debugging), otherwise
        // fall back to the session token persisted by `tenzro auth`, so
        // privileged commands work after login without manually exporting
        // TENZRO_BEARER_JWT.
        let bearer_token = session_token_for(&self.rpc_url);
        if let Some(ref bearer) = bearer_token {
            req = req.header("Authorization", format!("DPoP {}", bearer));
        }
        // A DPoP proof is per-request: it commits to this method and URL,
        // carries a `jti` the node caches against replay, and is valid for
        // ±60s. So it is minted here rather than exported — an env var can
        // only ever carry one that works once.
        //
        // `TENZRO_DPOP_PROOF` still wins when set, for debugging and for
        // callers holding their key somewhere this process cannot reach.
        if let Ok(dpop) = std::env::var("TENZRO_DPOP_PROOF")
            && !dpop.is_empty()
        {
            req = req.header("DPoP", dpop);
        } else if crate::dpop::DpopKey::exists() {
            // Only when a bearer token is present: the proof binds to it via
            // `ath`, and an unbound proof authorises nothing on its own.
            if let Some(ref token) = bearer_token {
                match crate::dpop::DpopKey::load().and_then(|k| k.proof("POST", url, Some(token))) {
                    Ok(proof) => req = req.header("DPoP", proof),
                    // A key that will not load or sign is worth saying so
                    // about: the request would otherwise fail at the node
                    // with a bare "missing DPoP proof".
                    Err(e) => eprintln!("warning: could not mint a DPoP proof: {e}"),
                }
            }
        }
        req
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
    let tnzo = wei as f64 / 1e18;
    if tnzo == (tnzo as u128) as f64 {
        format!("{} TNZO", tnzo as u128)
    } else {
        format!("{:.6} TNZO", tnzo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(body: &str) -> JsonRpcResponse {
        serde_json::from_str(body).expect("a JSON-RPC response")
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
mod nonce_and_chain_id_tests {
    use super::*;

    /// A node at a loopback port that answers each JSON-RPC method from
    /// `answers` (a method with no entry gets a JSON-RPC error). Returns the
    /// URL it serves.
    async fn node_answering(answers: &'static [(&'static str, &'static str)]) -> String {
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
}
