//! JSON-RPC client for communicating with Tenzro nodes

use serde::{Deserialize, Serialize};
use serde_json::Value;
use anyhow::Result;

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
        // rpc.tenzro.network → api.tenzro.network
        // Derive Web API URL from RPC URL:
        // - localhost:8545 → localhost:8080
        // - localhost:18545 → localhost:18080 (test ports: subtract 465)
        // - rpc.tenzro.network → api.tenzro.network
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
        }
    }

    /// Get the RPC URL
    pub fn url(&self) -> &str {
        &self.rpc_url
    }

    /// Make a JSON-RPC call.
    ///
    /// Forwards `Authorization: DPoP <jwt>` and `DPoP: <proof>` headers
    /// when the `TENZRO_BEARER_JWT` and `TENZRO_DPOP_PROOF` env vars are set.
    /// Auth-sensitive RPCs (signing, escrow, settlement) require these; public
    /// RPCs (balance/status/block reads) work without them.
    pub async fn call<T: serde::de::DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        let id = self.request_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            method,
            params,
            id,
        };

        let mut req = self.http.post(&self.rpc_url).json(&request);
        if let Ok(bearer) = std::env::var("TENZRO_BEARER_JWT") {
            if !bearer.is_empty() {
                req = req.header("Authorization", format!("DPoP {}", bearer));
            }
        }
        if let Ok(dpop) = std::env::var("TENZRO_DPOP_PROOF") {
            if !dpop.is_empty() {
                req = req.header("DPoP", dpop);
            }
        }

        let response = req.send().await?;

        let body: JsonRpcResponse<T> = response.json().await?;

        if let Some(err) = body.error {
            anyhow::bail!("RPC error [{}]: {}", err.code, err.message);
        }

        body.result.ok_or_else(|| anyhow::anyhow!("Empty RPC response"))
    }

    /// Make a GET request to the Web API
    pub async fn api_get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", self.api_url, path);
        let response = self.http.get(&url).send().await?;
        let body: T = response.json().await?;
        Ok(body)
    }

    /// Make a POST request to the Web API
    pub async fn api_post<T: serde::de::DeserializeOwned>(&self, path: &str, body: &Value) -> Result<T> {
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

        let client2 = RpcClient::new("https://rpc.tenzro.network");
        assert_eq!(client2.api_url, "https://api.tenzro.network");
    }
}
