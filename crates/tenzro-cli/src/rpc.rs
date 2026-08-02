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
    /// Optional explicit override for the `X-Tenzro-Api-Key` header.
    /// When set, takes precedence over `TENZRO_API_KEY` env var.
    api_key_override: Option<String>,
    /// Optional explicit override for the `X-Tenzro-Admin-Token` header.
    /// When set, takes precedence over `TENZRO_ADMIN_TOKEN` env var.
    /// Required for admin RPCs (`tenzro_createApiKey`, `tenzro_revokeApiKey`,
    /// `tenzro_listApiKeys`, `tenzro_resetCircuitBreaker`).
    admin_token_override: Option<String>,
    /// Target Canton network for canton-scoped methods. Merged into the
    /// request params as `canton_network` — the node reads it from the
    /// params rather than a header, so a caller can name one of several
    /// networks its key authorizes. Omitted means "the operator default".
    canton_network: Option<String>,
}

/// Whether a method routes to Canton, matching how the node decides which
/// requests carry a Canton scope: any `tenzro_` method naming Canton or
/// DAML, in either the CamelCase (`tenzro_listCantonDomains`) or
/// snake-case (`tenzro_canton_health`) form.
fn is_canton_method(method: &str) -> bool {
    method.starts_with("tenzro_")
        && (method.contains("Canton")
            || method.contains("canton")
            || method.contains("Daml")
            || method.contains("daml"))
}

#[derive(Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'a str,
    method: &'a str,
    params: Value,
    id: u64,
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

impl RpcClient {
    /// Create a new RPC client
    pub fn new(rpc_url: &str) -> Self {
        // Derive API URL from RPC URL
        // localhost:8545 → localhost:8080
        // localhost:9944 → localhost:8080
        // rpc.tenzro.xyz → api.tenzro.xyz
        // Derive Web API URL from RPC URL:
        // - localhost:8545 → localhost:8080
        // - localhost:18545 → localhost:18080 (test ports: subtract 465)
        // - rpc.tenzro.xyz → api.tenzro.xyz
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
            http: reqwest::Client::new(),
            rpc_url: rpc_url.to_string(),
            api_url,
            request_id: std::sync::atomic::AtomicU64::new(1),
            api_key_override: None,
            admin_token_override: None,
            canton_network: None,
        }
    }

    /// Get the RPC URL
    pub fn url(&self) -> &str {
        &self.rpc_url
    }

    /// Set an explicit `X-Tenzro-Api-Key` value, overriding the
    /// `TENZRO_API_KEY` env var. Empty strings are ignored.
    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        let key = key.into();
        if !key.is_empty() {
            self.api_key_override = Some(key);
        }
        self
    }

    /// Set an explicit `X-Tenzro-Admin-Token` value, overriding the
    /// `TENZRO_ADMIN_TOKEN` env var. Empty strings are ignored.
    /// Required for admin RPCs (key issuance, revocation, listing,
    /// circuit-breaker reset).
    pub fn with_admin_token(mut self, token: impl Into<String>) -> Self {
        let token = token.into();
        if !token.is_empty() {
            self.admin_token_override = Some(token);
        }
        self
    }

    /// Name the Canton network canton-scoped calls should target. Merged
    /// into the params of every canton-scoped method as `canton_network`.
    /// A key authorizing exactly one network does not need this; a key
    /// authorizing several does, and the node answers `-32602` naming the
    /// authorized set when it is missing. Empty strings are ignored.
    pub fn with_canton_network(mut self, network: impl Into<String>) -> Self {
        let network = network.into();
        if !network.is_empty() {
            self.canton_network = Some(network);
        }
        self
    }

    /// Make a JSON-RPC call.
    ///
    /// Forwards `Authorization: DPoP <jwt>` and `DPoP: <proof>` headers
    /// when the `TENZRO_BEARER_JWT` and `TENZRO_DPOP_PROOF` env vars are set.
    /// Auth-sensitive RPCs (signing, escrow, settlement) require these; public
    /// RPCs (balance/status/block reads) work without them.
    ///
    /// Forwards `X-Tenzro-Api-Key: <key>` when `TENZRO_API_KEY` is set —
    /// required for scoped RPCs (currently `tenzro_*Canton*`) that the
    /// node mediates on the caller's behalf.
    pub async fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> Result<T> {
        let id = self
            .request_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Canton network selection travels in the params, not a header. A
        // network already named by the caller wins over the client-wide one.
        let params = match (&self.canton_network, params) {
            (Some(network), Value::Object(mut map))
                if is_canton_method(method) && !map.contains_key("canton_network") =>
            {
                map.insert("canton_network".to_string(), Value::String(network.clone()));
                Value::Object(map)
            }
            (_, params) => params,
        };
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            method,
            params,
            id,
        };

        let mut req = self.http.post(&self.rpc_url).json(&request);
        if let Ok(bearer) = std::env::var("TENZRO_BEARER_JWT")
            && !bearer.is_empty()
        {
            req = req.header("Authorization", format!("DPoP {}", bearer));
        }
        if let Ok(dpop) = std::env::var("TENZRO_DPOP_PROOF")
            && !dpop.is_empty()
        {
            req = req.header("DPoP", dpop);
        }
        if let Some(ref api_key) = self.api_key_override {
            req = req.header("X-Tenzro-Api-Key", api_key);
        } else if let Ok(api_key) = std::env::var("TENZRO_API_KEY")
            && !api_key.is_empty()
        {
            req = req.header("X-Tenzro-Api-Key", api_key);
        }
        // Admin token for operator RPCs (`tenzro_createApiKey`,
        // `tenzro_revokeApiKey`, `tenzro_listApiKeys`,
        // `tenzro_resetCircuitBreaker`). See docs/api-keys.md.
        if let Some(ref admin) = self.admin_token_override {
            req = req.header("X-Tenzro-Admin-Token", admin);
        } else if let Ok(admin) = std::env::var("TENZRO_ADMIN_TOKEN")
            && !admin.is_empty()
        {
            req = req.header("X-Tenzro-Admin-Token", admin);
        }

        let response = req.send().await?;

        let body: JsonRpcResponse<T> = response.json().await?;

        if let Some(err) = body.error {
            anyhow::bail!("RPC error [{}]: {}", err.code, err.message);
        }

        body.result
            .ok_or_else(|| anyhow::anyhow!("Empty RPC response"))
    }

    /// Make a GET request to the Web API
    pub async fn api_get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", self.api_url, path);
        let response = self.http.get(&url).send().await?;
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
        let response = self.http.post(&url).json(body).send().await?;
        let result: T = response.json().await?;
        Ok(result)
    }
}

/// Parse a hex string (with or without 0x prefix) to u128
pub fn parse_hex_u128(hex: &str) -> u128 {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    u128::from_str_radix(hex, 16).unwrap_or(0)
}

/// Parse a hex string (with or without 0x prefix) to u64
pub fn parse_hex_u64(hex: &str) -> u64 {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    u64::from_str_radix(hex, 16).unwrap_or(0)
}

/// Read the dispensed amount out of a `tenzro_faucet` response.
///
/// The node reports `amount_wei` as a decimal string; the amount is set by
/// the genesis faucet config, so the client never assumes a figure of its own.
pub fn faucet_amount(resp: &serde_json::Value) -> Option<u128> {
    resp.get("amount_wei")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u128>().ok())
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

        let client2 = RpcClient::new("https://rpc.tenzro.xyz");
        assert_eq!(client2.api_url, "https://api.tenzro.xyz");
    }
}
