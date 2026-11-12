//! Discover and call any method a Tenzro node serves.
//!
//! The typed clients elsewhere in this crate cover the surfaces worth a
//! dedicated, documented signature — wallets, inference, storage, databases.
//! This covers everything else.
//!
//! It exists because the alternative does not work. A node serves several hundred JSON-RPC
//! methods and gains more with each release; an SDK that hand-wraps them is
//! always some months behind the node it is talking to, and the developer who
//! hits that gap discovers it at the moment they need the method. Here the
//! method list comes *from the node*, so a newer node simply reports more.
//!
//! Authorization is unchanged. A call through this gateway runs behind the same
//! access policy and default-deny classification as any other call — it
//! reaches exactly what your access token already allows.

use crate::error::{SdkError, SdkResult};
use crate::rpc::RpcClient;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;

/// How a method is gated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateClass {
    /// The node's operator and the administrators its access policy names.
    Admin,
    /// Open to any caller; the handler requires a proof from the owner of
    /// what it changes.
    Owner,
    /// Open to any caller the access policy admits.
    Open,
    /// Held for a feature not active on this network yet; every call refuses.
    Reserved,
}

/// One method in the node's directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodEntry {
    /// The JSON-RPC method name.
    pub method: String,
    /// How the dispatcher classifies it.
    pub gate: GateClass,
    /// The method class the node's access policy decides it under.
    pub class: String,
    /// The method's namespace, for grouping.
    pub namespace: String,
}

/// The node's method directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodDirectory {
    /// Matching methods.
    pub methods: Vec<MethodEntry>,
    /// How many matched.
    pub count: usize,
    /// How many the node serves in total, before filtering.
    pub total: usize,
    /// Every namespace the node has, so a caller can narrow a second query.
    pub namespaces: Vec<String>,
}

/// Discover and call any method.
pub struct GatewayClient {
    rpc: Arc<RpcClient>,
}

impl GatewayClient {
    /// Creates a new gateway client.
    pub fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Every method this node serves, with how each is gated.
    ///
    /// `namespace` and `contains` narrow the listing; the unfiltered directory
    /// has several hundred entries.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let dir = client.gateway().methods(None, Some("forecast")).await?;
    /// for m in &dir.methods {
    ///     println!("{} ({:?})", m.method, m.gate);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn methods(
        &self,
        namespace: Option<&str>,
        contains: Option<&str>,
    ) -> SdkResult<MethodDirectory> {
        let mut body = serde_json::Map::new();
        if let Some(n) = namespace {
            body.insert("namespace".into(), json!(n));
        }
        if let Some(c) = contains {
            body.insert("contains".into(), json!(c));
        }
        let result = self
            .rpc
            .call("tenzro_listRpcMethods", json!([Value::Object(body)]))
            .await?;
        serde_json::from_value(result)
            .map_err(|e| SdkError::RpcError(format!("Failed to parse method directory: {e}")))
    }

    /// Whether this node serves `method`.
    ///
    /// Asks the node rather than consulting a list compiled into this crate,
    /// so it stays correct against a node newer than the SDK.
    pub async fn supports(&self, method: &str) -> SdkResult<bool> {
        let dir = self.methods(None, Some(method)).await?;
        Ok(dir.methods.iter().any(|m| m.method == method))
    }

    /// Call any method by name, returning its raw result.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # use serde_json::json;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let plan = client
    ///     .gateway()
    ///     .call("tenzro_previewServe", json!({ "model_id": "qwen3-0.6b" }))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn call(&self, method: &str, params: Value) -> SdkResult<Value> {
        // Wrapped in the positional array the node normalizes back to named
        // params, matching every other call in this crate.
        self.rpc.call(method, json!([params])).await
    }

    /// Call any method and deserialize its result into `T`.
    pub async fn call_typed<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> SdkResult<T> {
        let value = self.call(method, params).await?;
        serde_json::from_value(value)
            .map_err(|e| SdkError::RpcError(format!("Failed to parse {method} result: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_gate_class_matches_the_nodes_wire_form() {
        // The node serializes these snake_case; a mismatch here turns every
        // directory listing into a parse error.
        assert_eq!(json!(GateClass::Admin), json!("admin"));
        assert_eq!(json!(GateClass::Open), json!("open"));
    }

    #[test]
    fn a_directory_entry_parses_with_its_gate_and_class() {
        let entry: MethodEntry = serde_json::from_value(json!({
            "method": "tenzro_queryEvents", "gate": "open",
            "class": "index", "namespace": "query",
        }))
        .expect("parses");
        assert_eq!(entry.gate, GateClass::Open);
        assert_eq!(entry.class, "index");
    }

    #[test]
    fn a_directory_parses() {
        let dir: MethodDirectory = serde_json::from_value(json!({
            "methods": [{"method": "eth_chainId", "gate": "open", "class": "read", "namespace": "eth"}],
            "count": 1, "total": 924, "namespaces": ["eth", "tenzro"],
        }))
        .expect("parses");
        assert_eq!(dir.count, 1);
        assert_eq!(dir.total, 924);
        assert_eq!(dir.methods[0].gate, GateClass::Open);
    }
}
