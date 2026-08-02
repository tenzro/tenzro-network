//! `tenzro rpc` — discover and call any method the node serves.
//!
//! The 100-odd command modules beside this one cover the workflows worth a
//! dedicated, documented command. This covers everything else, so nothing the
//! node can do is out of reach from the CLI — including methods added to a node
//! newer than this binary, because the directory comes from the node rather
//! than a list compiled in here.
//!
//! Authorization is unchanged: a call runs behind the same admin-token gate,
//! API-key scope gate, and default-deny classification as any other, so it
//! reaches exactly what the credentials you present already allow.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

/// Discover and call any JSON-RPC method
#[derive(Debug, Subcommand)]
pub enum RpcCommand {
    /// List the methods this node serves, with how each is gated
    Methods(RpcMethodsCmd),
    /// Call any method by name
    Call(RpcCallCmd),
}

impl RpcCommand {
    pub async fn execute(self) -> Result<()> {
        match self {
            Self::Methods(c) => c.execute().await,
            Self::Call(c) => c.execute().await,
        }
    }
}

fn client(rpc: &str, api_key: Option<&str>, admin_token: Option<&str>) -> RpcClient {
    let mut c = RpcClient::new(rpc);
    if let Some(k) = api_key {
        c = c.with_api_key(k.to_string());
    }
    if let Some(t) = admin_token {
        c = c.with_admin_token(t.to_string());
    }
    c
}

#[derive(Debug, Parser)]
pub struct RpcMethodsCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// Restrict to one namespace (`eth`, `canton`, …)
    #[arg(long)]
    namespace: Option<String>,
    /// Case-insensitive substring of the method name
    #[arg(long)]
    contains: Option<String>,
    /// List the namespaces rather than the methods
    #[arg(long)]
    namespaces: bool,
}

impl RpcMethodsCmd {
    pub async fn execute(self) -> Result<()> {
        let mut params = serde_json::json!({});
        if let Some(n) = &self.namespace {
            params["namespace"] = serde_json::json!(n);
        }
        if let Some(c) = &self.contains {
            params["contains"] = serde_json::json!(c);
        }
        let result: serde_json::Value = client(&self.rpc, None, None)
            .call("tenzro_listRpcMethods", params)
            .await
            .context("listing methods")?;

        if self.namespaces {
            output::print_header("Namespaces");
            println!();
            for n in result["namespaces"].as_array().unwrap_or(&vec![]) {
                println!("  {}", n.as_str().unwrap_or_default());
            }
            return Ok(());
        }

        let rows = result["methods"].as_array().cloned().unwrap_or_default();
        output::print_header("RPC Methods");
        println!();
        output::print_field(
            "Matched",
            &format!(
                "{} of {} served",
                rows.len(),
                result["total"].as_u64().unwrap_or(0)
            ),
        );
        println!();
        for m in &rows {
            let name = m["method"].as_str().unwrap_or("?");
            let gate = m["gate"].as_str().unwrap_or("open");
            // The scope is the operationally useful half: "admin" tells you to
            // stop, a scope tells you which key to go and get.
            let scope = m
                .get("scope")
                .and_then(|s| s.as_str())
                .map(|s| format!("  scope:{s}"))
                .unwrap_or_default();
            let marker = if gate == "admin" { "admin" } else { "open " };
            println!("  [{marker}] {name}{scope}");
        }
        if rows.is_empty() {
            output::print_info("No methods matched. Try a broader --contains, or --namespaces.");
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct RpcCallCmd {
    /// Method name, e.g. `tenzro_previewServe`
    method: String,
    /// Parameters as a JSON object. Defaults to `{}`.
    #[arg(long, default_value = "{}")]
    params: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// API key, for scope-gated methods. Falls back to `TENZRO_API_KEY`.
    #[arg(long)]
    api_key: Option<String>,
    /// Operator admin token, for admin-gated methods. Falls back to
    /// `TENZRO_ADMIN_TOKEN`.
    #[arg(long)]
    admin_token: Option<String>,
}

impl RpcCallCmd {
    pub async fn execute(self) -> Result<()> {
        let params: serde_json::Value = serde_json::from_str(&self.params)
            .with_context(|| format!("--params is not valid JSON: {}", self.params))?;
        let result: serde_json::Value = client(
            &self.rpc,
            self.api_key.as_deref(),
            self.admin_token.as_deref(),
        )
        .call(&self.method, params)
        .await
        .with_context(|| format!("calling {}", self.method))?;
        // Raw JSON, not a formatted rendering: a generic caller is either
        // reading it themselves or piping it into jq, and inventing a layout
        // for an arbitrary result would help neither.
        println!("{}", serde_json::to_string_pretty(&result)?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn params_must_be_valid_json() {
        // Caught before the request, so the error names the flag rather than
        // surfacing as a confusing server-side parse failure.
        assert!(serde_json::from_str::<serde_json::Value>("{not json").is_err());
        assert!(serde_json::from_str::<serde_json::Value>("{}").is_ok());
        assert!(serde_json::from_str::<serde_json::Value>(r#"{"model_id":"x"}"#).is_ok());
    }
}
