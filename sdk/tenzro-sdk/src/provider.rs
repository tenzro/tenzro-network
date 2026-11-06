//! Provider client for Tenzro Network
//!
//! This module provides functionality for network participation, model serving,
//! and provider operations.

use crate::error::{SdkError, SdkResult};
use crate::rpc::RpcClient;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;

/// Provider client for network participation and model serving
pub struct ProviderClient {
    rpc: Arc<RpcClient>,
}

impl ProviderClient {
    /// Creates a new provider client
    pub fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Start serving a model on the network with default placement.
    ///
    /// When a model is too large for a single host, the node auto-clusters:
    /// it reads the GGUF header for layer count and hidden dimension,
    /// discovers LAN members from gossiped cluster announcements, and runs a
    /// layer-wise pipeline across them. No extra arguments are required — the
    /// node decides single-host vs. cluster from the model shape and the
    /// reachable members. Use [`serve_model_with`](Self::serve_model_with) to
    /// force a cluster, force single-host, or serve privately.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let provider = client.provider();
    /// provider.serve_model("gemma4-9b").await?;
    /// println!("Now serving model");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn serve_model(&self, model_id: &str) -> SdkResult<()> {
        self.serve_model_with(model_id, ServeOptions::default())
            .await
    }

    /// Start serving a model with explicit options.
    ///
    /// - `max_concurrent`: the concurrent requests the operator admits for
    ///   this model; `None` lets the node size it.
    /// - `load_drafter`: `Some(false)` skips loading the catalog drafter for
    ///   multi-token prediction; the node loads it otherwise.
    /// - `visibility`: an override for this model. `Public` announces it and
    ///   any caller may invoke it by paying the operator's price; `Gated`
    ///   announces it as key-required; `Private` does not announce it and only
    ///   the node's own callers may invoke it. `None` (the default) follows the
    ///   node's visibility.
    ///
    /// Use [`DiscoveryClient::moe_plan_dispatch`](crate::discovery::DiscoveryClient::moe_plan_dispatch)
    /// first to preview how the experts split before serving.
    pub async fn serve_model_with(&self, model_id: &str, opts: ServeOptions) -> SdkResult<()> {
        let mut params = serde_json::Map::new();
        params.insert("model_id".into(), json!(model_id));
        if let Some(n) = opts.max_concurrent {
            params.insert("max_concurrent".into(), json!(n));
        }
        if let Some(load) = opts.load_drafter {
            params.insert("load_drafter".into(), json!(load));
        }
        if let Some(visibility) = opts.visibility {
            params.insert("visibility".into(), json!(visibility.as_str()));
        }
        self.rpc
            .call::<serde_json::Value>("tenzro_serveModel", Value::Object(params))
            .await?;
        Ok(())
    }

    /// Stop serving a model
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let provider = client.provider();
    /// provider.stop_model("gemma4-9b").await?;
    /// println!("Stopped serving model");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn stop_model(&self, model_id: &str) -> SdkResult<()> {
        self.rpc
            .call::<serde_json::Value>("tenzro_stopModel", json!({ "model_id": model_id }))
            .await?;
        Ok(())
    }

    /// Delete a downloaded model
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let provider = client.provider();
    /// provider.delete_model("gemma4-9b").await?;
    /// println!("Model deleted");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn delete_model(&self, model_id: &str) -> SdkResult<()> {
        self.rpc
            .call::<serde_json::Value>("tenzro_deleteModel", json!({ "model_id": model_id }))
            .await?;
        Ok(())
    }

    /// Chat with a loaded model
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # use tenzro_sdk::provider::ChatMessage;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let provider = client.provider();
    /// let messages = vec![ChatMessage::user("What is Tenzro Network?")];
    /// let response = provider.chat("gemma4-9b", messages).await?;
    /// println!("Response: {}", response.response);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn chat(
        &self,
        model_id: &str,
        messages: Vec<ChatMessage>,
    ) -> SdkResult<ChatResponse> {
        let result = self
            .rpc
            .call(
                "tenzro_chat",
                json!({ "model_id": model_id, "messages": messages }),
            )
            .await?;
        parse_rich_chat_response(result)
    }

    /// Send a chat completion with generation options. Use this when
    /// you need to pass [`ChatOptions`] (Multi-Token Prediction
    /// `draft_n`, max_tokens, temperature, top_p, etc.).
    ///
    /// MTP throughput uplift requires the target model to declare a
    /// drafter in its catalog entry (`HfModelEntry.drafter_id` +
    /// `mtp_kind`). Gemma 4 12B and 31B currently advertise this. When
    /// `draft_n` is set on a model whose runtime cannot satisfy it,
    /// the node returns a structured `MtpUnavailable` error.
    pub async fn chat_with(
        &self,
        model_id: &str,
        messages: Vec<ChatMessage>,
        opts: ChatOptions,
    ) -> SdkResult<ChatResponse> {
        let mut params = json!({
            "model_id": model_id,
            "messages": messages,
        });
        if let Some(t) = opts.temperature {
            params["temperature"] = json!(t);
        }
        if let Some(p) = opts.top_p {
            params["top_p"] = json!(p);
        }
        if let Some(m) = opts.max_tokens {
            params["max_tokens"] = json!(m);
        }
        if let Some(n) = opts.draft_n {
            params["draft_n"] = json!(n);
        }
        let result = self.rpc.call("tenzro_chat", params).await?;
        parse_rich_chat_response(result)
    }

    /// Get hardware profile of the node
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let provider = client.provider();
    /// let profile = provider.get_hardware_profile().await?;
    /// println!("CPU: {}", profile.cpu_model);
    /// println!("Memory: {} GB", profile.total_ram_gb);
    /// for gpu in &profile.gpus {
    ///     println!("{:?} {} ({} GiB)", gpu.vendor, gpu.name, gpu.vram_gb);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_hardware_profile(&self) -> SdkResult<HardwareProfile> {
        let result = self
            .rpc
            .call("tenzro_getHardwareProfile", json!([]))
            .await?;
        serde_json::from_value(result)
            .map_err(|e| SdkError::RpcError(format!("Failed to parse hardware profile: {}", e)))
    }

    /// Set this node's active roles. One stake backs every role.
    ///
    /// `roles` is a comma-separated set of role tokens: `validator`, `ai`,
    /// `storage`, `tee`, `user`. The empty string resolves to a client node.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let provider = client.provider();
    /// provider.set_roles("validator,storage,ai").await?;
    /// println!("Roles updated");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn set_roles(&self, roles: &str) -> SdkResult<()> {
        self.rpc
            .call::<serde_json::Value>("tenzro_setRole", json!([{ "roles": roles }]))
            .await?;
        Ok(())
    }

    /// Get this node's active roles (normalized role-token strings).
    pub async fn get_roles(&self) -> SdkResult<Vec<String>> {
        let result: serde_json::Value = self.rpc.call("tenzro_getRole", json!([])).await?;
        let roles = result
            .get("roles")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        Ok(roles)
    }

    /// Get provider statistics
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let provider = client.provider();
    /// let stats = provider.stats().await?;
    /// println!("Requests: {}", stats.total_requests);
    /// println!("Served models: {}", stats.served_models);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn stats(&self) -> SdkResult<ProviderStats> {
        let result = self.rpc.call("tenzro_getProviderStats", json!({})).await?;
        serde_json::from_value(result)
            .map_err(|e| SdkError::RpcError(format!("Failed to parse provider stats: {}", e)))
    }

    /// List all model service endpoints with load information
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let provider = client.provider();
    /// let endpoints = provider.list_model_endpoints().await?;
    /// for ep in &endpoints {
    ///     println!("{}: {} ({})", ep.model_name, ep.status, ep.location);
    ///     if let Some(load) = &ep.load {
    ///         println!("  Load: {}/{} ({}%)", load.active_requests, load.max_concurrent, load.utilization_percent);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list_model_endpoints(&self) -> SdkResult<Vec<ModelEndpoint>> {
        let result = self
            .rpc
            .call("tenzro_listModelEndpoints", json!([]))
            .await?;
        serde_json::from_value(result)
            .map_err(|e| SdkError::RpcError(format!("Failed to parse model endpoints: {}", e)))
    }

    /// Get load information for a specific model
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let provider = client.provider();
    /// if let Some(load) = provider.get_model_load("gemma3-270m").await? {
    ///     println!("Load: {}/{} ({}%)", load.active_requests, load.max_concurrent, load.utilization_percent);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_model_load(&self, model_id: &str) -> SdkResult<Option<ModelLoad>> {
        let endpoints: Vec<ModelEndpoint> = self.list_model_endpoints().await?;
        Ok(endpoints
            .into_iter()
            .find(|ep| ep.model_id == model_id || ep.model_name == model_id)
            .and_then(|ep| ep.load))
    }

    /// Joins as a micro node (light participant). The wallet is bound to the
    /// caller's identity key; the node never mints one.
    pub async fn join_as_micro_node(
        &self,
        identity: &MicroNodeIdentity,
        display_name: Option<&str>,
        participant_type: Option<&str>,
    ) -> SdkResult<serde_json::Value> {
        let mut params = serde_json::Map::new();
        params.insert("public_key".into(), json!(identity.public_key()));
        match identity {
            MicroNodeIdentity::Human { credential_id, .. } => {
                params.insert("credential_id".into(), json!(credential_id));
            }
            MicroNodeIdentity::Machine { machine_id, .. } => {
                params.insert("machine_id".into(), json!(machine_id));
            }
        }
        if let Some(name) = display_name {
            params.insert("display_name".into(), json!(name));
        }
        if let Some(kind) = participant_type {
            params.insert("participant_type".into(), json!(kind));
        }
        self.rpc
            .call("tenzro_joinAsMicroNode", Value::Object(params))
            .await
    }

    /// What serving `model_id` would take on this node (memory, quantization,
    /// context and concurrency), without loading it.
    pub async fn preview_serve(
        &self,
        model_id: &str,
        quant: Option<&str>,
        context_length: Option<u32>,
        max_concurrent: Option<u32>,
    ) -> SdkResult<serde_json::Value> {
        let mut params = serde_json::Map::new();
        params.insert("model_id".into(), json!(model_id));
        if let Some(q) = quant {
            params.insert("quant".into(), json!(q));
        }
        if let Some(n) = context_length {
            params.insert("context_length".into(), json!(n));
        }
        if let Some(n) = max_concurrent {
            params.insert("max_concurrent".into(), json!(n));
        }
        self.rpc
            .call("tenzro_previewServe", Value::Object(params))
            .await
    }

    /// Gets the node's model stacks: the one serving now and until when, the
    /// next one and when it starts, and every configured stack
    pub async fn get_model_stacks(&self) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_getModelStacks", serde_json::json!([]))
            .await
    }

    /// Sets this node's price cards: `{ "default": RateCard, "models": {
    /// "<model_id>": RateCard } }`, each card as [`crate::pricing::RateCard`]
    /// serializes. Operator only.
    pub async fn set_provider_pricing(
        &self,
        pricing: serde_json::Value,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_setProviderPricing", serde_json::json!(pricing))
            .await
    }

    /// Gets this node's price cards: the default card and per-model cards.
    pub async fn get_provider_pricing(&self) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_getProviderPricing", serde_json::json!([]))
            .await
    }

    /// Gets a specific model endpoint by instance_id or model_id
    pub async fn get_model_endpoint(&self, instance_id: &str) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getModelEndpoint",
                serde_json::json!({"instance_id": instance_id}),
            )
            .await
    }

    /// Registers a remote model endpoint
    pub async fn register_model_endpoint(
        &self,
        model_id: &str,
        mcp_endpoint: Option<&str>,
        model_name: Option<&str>,
        provider_name: Option<&str>,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_registerModelEndpoint",
                serde_json::json!({"model_id": model_id, "mcp_endpoint": mcp_endpoint, "model_name": model_name, "provider_name": provider_name}),
            )
            .await
    }

    /// Unregisters a model endpoint
    pub async fn unregister_model_endpoint(
        &self,
        instance_id: &str,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_unregisterModelEndpoint",
                serde_json::json!({"instance_id": instance_id}),
            )
            .await
    }

    /// Gets the node status including health, block height, and peer count
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let provider = client.provider();
    /// let status = provider.get_node_status().await?;
    /// println!("Status: {:?}", status);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_node_status(&self) -> SdkResult<serde_json::Value> {
        self.rpc.call("tenzro_getNodeStatus", json!([])).await
    }

    /// Gets provider statistics for a specific address
    ///
    /// Returns measured performance, advertised capacity and role bonds.
    ///
    /// # Arguments
    ///
    /// * `address` - Provider address (hex)
    pub async fn get_provider_stats(&self, address: &str) -> SdkResult<ProviderStats> {
        let result = self
            .rpc
            .call("tenzro_getProviderStats", json!({ "address": address }))
            .await?;
        serde_json::from_value(result)
            .map_err(|e| SdkError::RpcError(format!("Failed to parse provider stats: {}", e)))
    }

    /// Read the compute-bond floor and withdrawal cooldown this node enforces.
    ///
    /// Call this before registering — a registration whose
    /// backing bond is below the floor is refused at admission.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let params = client.provider().compute_bond_params().await?;
    /// println!("Minimum bond: {} wei", params.min_bond_wei);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn compute_bond_params(&self) -> SdkResult<ComputeBondParams> {
        let result = self.rpc.call("tenzro_computeBondParams", json!([])).await?;
        serde_json::from_value(result)
            .map_err(|e| SdkError::RpcError(format!("Failed to parse compute bond params: {}", e)))
    }

    /// Fetch the compute bond posted against `provider_did`, or `None` when
    /// that provider has never posted one.
    ///
    /// # Arguments
    ///
    /// * `provider_did` - Provider DID (e.g. `did:tenzro:machine:...`)
    pub async fn get_compute_bond(&self, provider_did: &str) -> SdkResult<Option<ComputeBond>> {
        let result: serde_json::Value = self
            .rpc
            .call(
                "tenzro_getComputeBond",
                json!([{ "provider_did": provider_did }]),
            )
            .await?;
        if result.is_null() {
            return Ok(None);
        }
        serde_json::from_value(result)
            .map(Some)
            .map_err(|e| SdkError::RpcError(format!("Failed to parse compute bond: {}", e)))
    }

    /// List every compute bond this node knows about.
    pub async fn list_compute_bonds(&self) -> SdkResult<Vec<ComputeBond>> {
        let result: serde_json::Value = self.rpc.call("tenzro_listComputeBonds", json!([])).await?;
        let bonds = result.get("bonds").cloned().unwrap_or(json!([]));
        serde_json::from_value(bonds)
            .map_err(|e| SdkError::RpcError(format!("Failed to parse compute bonds: {}", e)))
    }

    /// List all providers discovered on the Tenzro Network via gossipsub announcements.
    ///
    /// Returns both the local node (if it is actively serving models) and all remote providers
    /// discovered via the `tenzro/providers` gossipsub topic. Each node serving models
    /// broadcasts a `ProviderAnnouncement` message every 60 seconds; this call merges the
    /// local provider entry with all gossipsub-discovered entries.
    ///
    /// # Example
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let provider = client.provider();
    /// let providers = provider.list_providers().await?;
    /// for p in &providers {
    ///     println!("{}: {} ({}) — models: {:?}",
    ///         p.endpoint_id, p.provider_type, p.status, p.served_models);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list_providers(&self) -> SdkResult<Vec<NetworkProvider>> {
        #[derive(Deserialize)]
        struct Page {
            providers: Vec<serde_json::Value>,
            next_cursor: Option<String>,
        }
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let result = self
                .rpc
                .call(
                    "tenzro_listProviders",
                    serde_json::json!({ "limit": 200, "cursor": cursor }),
                )
                .await?;
            let page: Page = serde_json::from_value(result).map_err(|e| {
                SdkError::RpcError(format!("Failed to parse list_providers response: {}", e))
            })?;
            // Nodes that serve delegated agents are listed by identity only;
            // this lists the providers that serve models.
            out.extend(
                page.providers
                    .into_iter()
                    .filter(|p| p.get("endpoint_id").is_some())
                    .map(serde_json::from_value::<NetworkProvider>)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| {
                        SdkError::RpcError(format!("Failed to parse a provider entry: {}", e))
                    })?,
            );
            match page.next_cursor {
                Some(c) => cursor = Some(c),
                None => return Ok(out),
            }
        }
    }

    /// Price one request for `model` at every provider serving it, cheapest
    /// first. `units` are the request's billable units (e.g.
    /// `{"input_tokens": 800, "output_tokens": 200}`; omitted units are
    /// zero); `verification` is `none`, `receipt`, `optimistic` or `tee`.
    pub async fn quote_inference(
        &self,
        model: &str,
        units: serde_json::Value,
        verification: Option<&str>,
        provider: Option<&str>,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_quoteInference",
                serde_json::json!({
                    "model": model,
                    "units": units,
                    "verification": verification,
                    "provider": provider,
                }),
            )
            .await
    }
}

/// Maps the node's rich chat envelope (Anthropic Messages-style:
/// `{model, content: [{type: "text", text}, ...], usage}`) into the flat
/// [`ChatResponse`]. Text blocks are concatenated; thinking/tool blocks
/// are skipped.
fn parse_rich_chat_response(result: serde_json::Value) -> SdkResult<ChatResponse> {
    let content = result
        .get("content")
        .and_then(|c| c.as_array())
        .ok_or_else(|| {
            SdkError::RpcError(format!(
                "chat response missing 'content' blocks: {}",
                result
            ))
        })?;
    let response = content
        .iter()
        .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
        .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
        .collect::<Vec<_>>()
        .join("");
    let model_id = result
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let usage = result.get("usage");
    let tokens_used = usage
        .and_then(|u| u.get("input_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        + usage
            .and_then(|u| u.get("output_tokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
    Ok(ChatResponse {
        response,
        model_id,
        tokens_used: tokens_used as u32,
    })
}

/// Who can find a resource and who may use it.
///
/// A node has one visibility that applies to every resource it offers; a served
/// model may override it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    /// Announced. Any caller may invoke it by paying the operator's per-use
    /// price (free at `0`), with no key, even on a node whose service-key gate
    /// is on.
    Public,
    /// Announced as access-required. Only callers the operator's access policy
    /// names may invoke it; there is no pay-per-use path.
    Gated,
    /// Not announced. Only the node's own callers may invoke it.
    Private,
}

impl Visibility {
    /// Wire string: `"public"`, `"gated"` or `"private"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Visibility::Public => "public",
            Visibility::Gated => "gated",
            Visibility::Private => "private",
        }
    }
}

/// Serving options for [`ProviderClient::serve_model_with`].
#[derive(Debug, Clone, Default)]
pub struct ServeOptions {
    /// Visibility override for this model. `None` follows the node's
    /// visibility.
    pub visibility: Option<Visibility>,
    /// Concurrent requests the operator admits for this model; `None` lets
    /// the node size it.
    pub max_concurrent: Option<u32>,
    /// `Some(false)` skips loading the catalog drafter for multi-token
    /// prediction; the node loads it otherwise.
    pub load_drafter: Option<bool>,
}

/// A provider's compute bond — the admission collateral `register` checks
/// before it will accept a provider onto a rung.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeBond {
    /// DID of the provider the bond is posted against
    pub provider_did: String,
    /// Address that posted the bond and receives the refund
    pub provider_address: String,
    /// Bonded amount in wei (10^-18 TNZO)
    pub amount: String,
    /// `Active`, `Cooldown`, `Returned`, or `Slashed`
    pub status: String,
    /// Unix milliseconds at which a withdrawal may be finalized; `None`
    /// unless the bond is in `Cooldown`
    pub cooldown_until: Option<i64>,
    /// The bond vault address, hex
    pub vault: String,
    /// Whether this bond can currently back a provider registration
    pub is_eligible: bool,
    /// Amount that counts toward admission in wei — zero once the bond
    /// leaves `Active`
    pub effective_amount: String,
}

/// The admission dials a provider needs before it posts a compute bond.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeBondParams {
    /// Minimum bond in wei the node will accept for admission. The operative
    /// requirement is the higher of this floor and the target rung's own bond
    pub min_bond_wei: String,
    /// Milliseconds a withdrawal sits in `Cooldown` before it can be finalized
    pub cooldown_ms: i64,
}

/// `tenzro_getProviderStats`: one provider's measured performance, advertised
/// capacity and role bonds.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProviderStats {
    /// Provider address
    pub address: String,
    /// Requests routed to it
    pub total_requests: u64,
    /// Requests that succeeded
    pub successful: u64,
    /// Requests that failed
    pub failed: u64,
    /// Mean latency, ms
    pub avg_latency_ms: u64,
    /// 95th percentile latency, ms, once there are samples
    pub p95_latency_ms: Option<u64>,
    /// Uptime, percent
    pub uptime_percentage: f64,
    /// Reputation, when the provider is registered
    pub reputation: Option<u64>,
    /// Inferences billed
    pub inference_count: u64,
    /// Input tokens billed
    pub total_input_tokens: u64,
    /// Output tokens billed
    pub total_output_tokens: u64,
    /// Measured decode throughput
    pub measured_tokens_per_sec: Option<f64>,
    /// Revenue in wei, decimal string
    pub total_revenue_wei: String,
    /// When it last served, ms since the epoch
    pub last_inference_ms: Option<i64>,
    /// Advertised concurrent requests
    pub max_concurrent: u32,
    /// Requests in flight
    pub current_active: u32,
    /// Advertised requests per second
    pub advertised_requests_per_second: u32,
    /// How many models this node serves
    pub served_models: u64,
    /// Role bonds from consensus state: role, bonded, required,
    /// entry_required, capacity, unbonding, release_at_ms, endpoint
    pub role_stakes: Vec<Value>,
    /// `Active` or `Idle`
    pub utilization: String,
}

/// The identity key a micro node's wallet is bound to.
#[derive(Debug, Clone)]
pub enum MicroNodeIdentity {
    /// A human, holding a passkey: the P-256 key (x || y, hex) and the
    /// passkey credential id (hex).
    Human {
        /// P-256 public key, x || y, hex
        public_key: String,
        /// Passkey credential id, hex
        credential_id: String,
    },
    /// A machine, holding a secure-element key.
    Machine {
        /// P-256 public key, x || y, hex
        public_key: String,
        /// The machine's id
        machine_id: String,
    },
}

impl MicroNodeIdentity {
    /// The identity's public key.
    pub fn public_key(&self) -> &str {
        match self {
            Self::Human { public_key, .. } | Self::Machine { public_key, .. } => public_key,
        }
    }
}

/// A chat message in a conversation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Message role (system, user, assistant, tool)
    pub role: String,
    /// Message content
    pub content: String,
    /// Calls an assistant turn made, echoed back in history.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<crate::chat::ToolCall>>,
    /// On a `tool` turn, the id of the call this message answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

impl ChatMessage {
    fn text(role: &str, content: impl Into<String>) -> Self {
        Self {
            role: role.to_string(),
            content: content.into(),
            ..Self::default()
        }
    }

    /// A system message.
    pub fn system(content: impl Into<String>) -> Self {
        Self::text("system", content)
    }

    /// A user message.
    pub fn user(content: impl Into<String>) -> Self {
        Self::text("user", content)
    }

    /// An assistant message.
    pub fn assistant(content: impl Into<String>) -> Self {
        Self::text("assistant", content)
    }

    /// The reply to tool call `tool_call_id`.
    pub fn tool(tool_call_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            tool_call_id: Some(tool_call_id.into()),
            ..Self::text("tool", content)
        }
    }
}

/// Response from a chat completion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    /// The generated response text
    pub response: String,
    /// Model ID that generated the response
    pub model_id: String,
    /// Number of tokens used
    pub tokens_used: u32,
}

/// Optional generation knobs for [`ProviderClient::chat_with`].
///
/// Use the `with_*` builder methods to set fields fluently; all
/// fields default to `None`, in which case the node falls back to
/// its own per-model defaults.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChatOptions {
    /// Sampling temperature (0.0..=2.0). Default: 0.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Top-p nucleus-sampling threshold. Default: 0.9.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    /// Maximum new tokens to generate. Default: 512.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Multi-Token-Prediction draft count (1..=6). Only meaningful on
    /// targets whose catalog entry declares a drafter
    /// (`HfModelEntry.mtp_kind == DraftMtp`). Unsloth recommends 2 as
    /// a starting point on Gemma 4; optimal value is hardware-
    /// dependent. When the runtime can't satisfy MTP the node returns
    /// a structured `MtpUnavailable` error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft_n: Option<u8>,
}

impl ChatOptions {
    /// Set the sampling temperature.
    pub fn with_temperature(mut self, t: f64) -> Self {
        self.temperature = Some(t);
        self
    }
    /// Set the top-p threshold.
    pub fn with_top_p(mut self, p: f64) -> Self {
        self.top_p = Some(p);
        self
    }
    /// Set the max-tokens cap.
    pub fn with_max_tokens(mut self, n: u32) -> Self {
        self.max_tokens = Some(n);
        self
    }
    /// Enable Multi-Token Prediction with the given draft count
    /// (clamped to 1..=6).
    pub fn with_draft_n(mut self, n: u8) -> Self {
        self.draft_n = Some(n.clamp(1, 6));
        self
    }
}

/// Accelerator vendor as reported by the node's hardware probe. Drives the
/// compute-capability interpretation and the FP8/FP4 derivation rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GpuVendor {
    /// NVIDIA — compute capability is the SM version string ("8.9", "9.0").
    Nvidia,
    /// AMD — compute capability is the gfx target ("gfx942", "gfx1100").
    Amd,
    /// Apple Silicon — unified-memory Metal GPU; no discrete VRAM.
    Apple,
    /// Any other accelerator (no precision derivation applied).
    Other,
}

/// A single accelerator discovered by the node's hardware probe. A node may
/// expose more than one, so [`HardwareProfile::gpus`] is a list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuDevice {
    /// Accelerator vendor.
    pub vendor: GpuVendor,
    /// Device marketing name (e.g. "NVIDIA H100 80GB HBM3", "Apple M3 Max").
    pub name: String,
    /// Device memory in GiB (unified-memory budget on Apple Silicon).
    pub vram_gb: u32,
    /// Vendor-native compute-capability string: SM version for NVIDIA, gfx
    /// target for AMD, "metal" for Apple. Empty when the probe could not read it.
    pub compute_capability: String,
    /// Hardware FP8 matrix/tensor units present.
    pub fp8: bool,
    /// Hardware FP4 matrix/tensor units present.
    pub fp4: bool,
}

/// Hardware profile of a node, as returned by `tenzro_getHardwareProfile`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareProfile {
    /// CPU model string.
    pub cpu_model: String,
    /// Physical core count.
    pub cpu_cores: usize,
    /// Logical thread count.
    pub cpu_threads: usize,
    /// Total system RAM in GB.
    pub total_ram_gb: f64,
    /// Every accelerator the node detected. Empty on a CPU-only node.
    pub gpus: Vec<GpuDevice>,
    /// Free storage in GB under the node's data dir.
    pub storage_available_gb: f64,
    /// Whether a TEE is available on this host.
    pub tee_available: bool,
    /// TEE vendor string when `tee_available` (e.g. "Intel TDX"), else `None`.
    pub tee_vendor: Option<String>,
    /// Operating system.
    pub os: String,
    /// CPU architecture.
    pub arch: String,
    /// Stable per-device fingerprint over the hardware's descriptive
    /// attributes — identifies a hardware class, not an individual unit.
    pub device_fingerprint: String,
    /// Hex SHA-256 over the machine's per-unit hardware identifiers (SMBIOS
    /// system UUID, baseboard serial, NVIDIA GPU UUIDs). `None` when the node
    /// can read none of them.
    pub hardware_root: Option<String>,
    /// Labels of the identifier sources behind `hardware_root`, e.g.
    /// `["dmi:product_uuid", "gpu:uuid"]`. Never carries serial values.
    pub hardware_root_sources: Vec<String>,
}

/// Load information for a model being served
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelLoad {
    /// Number of active inference requests
    pub active_requests: u32,
    /// Maximum concurrent requests supported
    pub max_concurrent: u32,
    /// Current utilization percentage (0-100)
    pub utilization_percent: u8,
    /// Load level classification
    pub load_level: String,
}

/// Model pricing information (TNZO per token)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPricing {
    /// Cost per input token in TNZO
    #[serde(default)]
    pub input_per_token: f64,
    /// Cost per output token in TNZO
    #[serde(default)]
    pub output_per_token: f64,
    /// Currency (always "TNZO")
    #[serde(default = "default_currency")]
    pub currency: String,
}

fn default_currency() -> String {
    "TNZO".to_string()
}

/// Model service endpoint information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelEndpoint {
    /// Model name
    pub model_name: String,
    /// Model ID
    #[serde(default)]
    pub model_id: String,
    /// Instance ID
    pub instance_id: String,
    /// MCP endpoint URL
    #[serde(default)]
    pub mcp_endpoint: String,
    /// Location (local or network)
    #[serde(default)]
    pub location: String,
    /// iroh EndpointId of the serving node (hex-encoded). Populated for
    /// network-discovered endpoints so callers can see the NAT-agnostic
    /// address a remote model is reached at. Empty for local services.
    #[serde(default)]
    pub iroh_endpoint_id: String,
    /// Provider name
    #[serde(default)]
    pub provider_name: String,
    /// Service status
    #[serde(default)]
    pub status: String,
    /// Availability: "local", "downloaded", "downloadable", or "network"
    #[serde(default)]
    pub availability: String,
    /// Pricing information
    #[serde(default)]
    pub pricing: Option<ModelPricing>,
    /// Load information (when serving)
    #[serde(default)]
    pub load: Option<ModelLoad>,
}

/// A provider discovered on the Tenzro Network via gossipsub announcements.
///
/// Providers are discovered via the `tenzro/providers` gossipsub topic.
/// Each node serving models broadcasts a `ProviderAnnouncement` every 60s and all
/// peers merge announcements into their `network_providers` cache.
///
/// Use [`ProviderClient::list_providers`] to discover providers via
/// the `tenzro_listProviders` JSON-RPC method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkProvider {
    /// iroh endpoint id of the announcing node
    #[serde(default)]
    pub endpoint_id: String,
    /// Wallet/account address of the provider
    pub provider_address: String,
    /// Provider type (e.g. "ai", "tee", "general")
    #[serde(default)]
    pub provider_type: String,
    /// Model IDs currently being served by this node
    #[serde(default)]
    pub served_models: Vec<String>,
    /// Capability labels (e.g. "inference", "tee-attestation")
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Lifecycle status (e.g. "active", "draining")
    #[serde(default)]
    pub status: String,
    /// Whether this is the local node
    #[serde(default)]
    pub is_local: bool,
    /// Coarse region: a country code or a wide region; `None` when the
    /// provider declared none
    #[serde(default)]
    pub region: Option<String>,
    /// Declared jurisdiction (ISO 3166-1 alpha-2)
    #[serde(default)]
    pub jurisdiction: Option<String>,
    /// Live load of each served model
    #[serde(default)]
    pub model_load: Option<Vec<ProviderModelLoad>>,
    /// When the load was read, ms since the Unix epoch
    #[serde(default)]
    pub load_as_of_ms: Option<i64>,
}

/// The live load of one model at a provider, as `tenzro_listProviders`
/// reports it for every provider (this node's read now, a peer's from its
/// latest heartbeat).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderModelLoad {
    /// The model
    pub model_id: String,
    /// `cold`, `warming`, `warm` or `evicting`
    pub state: String,
    /// Requests admitted and not yet finished
    pub in_flight: u32,
    /// Most requests it admits at once
    pub max_concurrent: u32,
    /// Requests waiting for it to finish loading
    pub queue_depth: u32,
    /// Estimated time until it is loaded, ms, while warming
    pub warm_eta_ms: Option<u64>,
}

impl ProviderClient {
    /// Calls `tenzro_getSealedModel`: get sealed model.
    pub async fn get_sealed_model(
        &self,
        model_id: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getSealedModel",
                serde_json::json!({ "model_id": model_id }),
            )
            .await
    }

    /// Calls `tenzro_listSealedModels`: list sealed models.
    pub async fn list_sealed_models(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_listSealedModels", serde_json::Value::Null)
            .await
    }

    /// Seals a model's weights on this node for the given recipients and
    /// signs the sealed-model manifest with the node's key.
    pub async fn seal_model(&self, request: &SealModelRequest) -> SdkResult<Value> {
        self.rpc
            .call("tenzro_sealModel", serde_json::to_value(request)?)
            .await
    }

    /// Installs a sealed model for `recipient_did`, from a manifest or from a
    /// model this node already holds a manifest for.
    pub async fn install_sealed_model(
        &self,
        request: &InstallSealedModelRequest,
    ) -> SdkResult<Value> {
        self.rpc
            .call("tenzro_installSealedModel", serde_json::to_value(request)?)
            .await
    }

    /// Calls `tenzro_modelRecipientKey`: model recipient key.
    pub async fn model_recipient_key(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_modelRecipientKey", serde_json::Value::Null)
            .await
    }

    /// Calls `tenzro_pruneModelRegistry`: prune model registry.
    pub async fn prune_model_registry(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_pruneModelRegistry", serde_json::Value::Null)
            .await
    }

    /// Calls `tenzro_getTerritoryPolicy`: get territory policy.
    pub async fn get_territory_policy(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_getTerritoryPolicy", serde_json::json!([]))
            .await
    }

    /// Calls `tenzro_modelLifecycle`: every warm model with its state and pin
    /// (`{ warm_count, warm }`), or with `model_id` that one model's
    /// `{ model_id, state, pinned }`.
    pub async fn model_lifecycle(
        &self,
        model_id: Option<&str>,
    ) -> crate::error::SdkResult<serde_json::Value> {
        let params = match model_id {
            Some(id) => serde_json::json!({ "model_id": id }),
            None => serde_json::json!({}),
        };
        self.rpc.call("tenzro_modelLifecycle", params).await
    }

    /// Calls `tenzro_moeExpertLoad`: moe expert load.
    pub async fn moe_expert_load(
        &self,
        model_id: &str,
        layer: u64,
        expert: u64,
        uri: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc.call("tenzro_moeExpertLoad", serde_json::json!({ "model_id": model_id, "layer": layer, "expert": expert, "uri": uri })).await
    }

    /// Calls `tenzro_moeExpertUnload`: moe expert unload.
    pub async fn moe_expert_unload(
        &self,
        model_id: &str,
        layer: u64,
        expert: u64,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_moeExpertUnload",
                serde_json::json!({ "model_id": model_id, "layer": layer, "expert": expert }),
            )
            .await
    }

    /// Calls `tenzro_moeGateLoad`: moe gate load.
    pub async fn moe_gate_load(
        &self,
        model_id: &str,
        layer: u64,
        uri: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_moeGateLoad",
                serde_json::json!({ "model_id": model_id, "layer": layer, "uri": uri }),
            )
            .await
    }

    /// Calls `tenzro_moeGateUnload`: moe gate unload.
    pub async fn moe_gate_unload(
        &self,
        model_id: &str,
        layer: u64,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_moeGateUnload",
                serde_json::json!({ "model_id": model_id, "layer": layer }),
            )
            .await
    }

    /// Calls `tenzro_moePrepareStatus`: moe prepare status.
    pub async fn moe_prepare_status(
        &self,
        job_id: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_moePrepareStatus",
                serde_json::json!({ "job_id": job_id }),
            )
            .await
    }
}

/// One recipient of a sealed model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealRecipient {
    /// The recipient's DID.
    pub did: String,
    /// The recipient's hybrid X25519 + ML-KEM-768 public key, 1216 bytes hex
    /// (from `tenzro_modelRecipientKey`).
    pub recipient_key: String,
    /// Enclave measurement the recipient must attest to, hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclave_measurement_hex: Option<String>,
}

/// Parameters of `tenzro_sealModel`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealModelRequest {
    /// Model identifier.
    pub model_id: String,
    /// Path of the weights on the node.
    pub path: String,
    /// DID of the model's owner.
    pub owner_did: String,
    /// Artifact name; the node derives one from `path` when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_name: Option<String>,
    /// Shard size in bytes; the node's default when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shard_bytes: Option<u64>,
    /// At least one recipient.
    pub recipients: Vec<SealRecipient>,
}

/// Parameters of `tenzro_installSealedModel`: give `manifest` or `model_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallSealedModelRequest {
    /// DID of the recipient installing the model.
    pub recipient_did: String,
    /// The signed sealed-model manifest, as `tenzro_sealModel` returned it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<Value>,
    /// Model whose manifest the node already stores.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
}

impl ProviderClient {
    /// Calls `tenzro_computeGetClaim`: compute get claim.
    pub async fn compute_get_claim(
        &self,
        claim_id: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_computeGetClaim",
                serde_json::json!({ "claim_id": claim_id }),
            )
            .await
    }

    /// Calls `tenzro_computeListClaims`: the compute claims `party` (an
    /// address) is a side of, `{ total, claims }`; `limit` defaults to 100.
    pub async fn compute_list_claims(
        &self,
        party: &str,
        limit: Option<u64>,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_computeListClaims",
                serde_json::json!({ "party": party, "limit": limit }),
            )
            .await
    }

    /// Calls `tenzro_computePriceFeed`: compute price feed.
    pub async fn compute_price_feed(
        &self,
        model_id: Option<&str>,
        region: Option<&str>,
        attested_only: Option<bool>,
        limit: Option<u64>,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc.call("tenzro_computePriceFeed", serde_json::json!({ "model_id": model_id, "region": region, "attested_only": attested_only, "limit": limit })).await
    }

    /// Calls `tenzro_buildModelManifest`: build model manifest.
    pub async fn build_model_manifest(
        &self,
        name: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_buildModelManifest",
                serde_json::json!({ "name": name }),
            )
            .await
    }

    /// Calls `tenzro_pinModel`: pin model.
    pub async fn pin_model(&self, model_id: &str) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_pinModel",
                serde_json::json!({ "model_id": model_id }),
            )
            .await
    }

    /// Calls `tenzro_unpinModel`: unpin model.
    pub async fn unpin_model(&self, model_id: &str) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_unpinModel",
                serde_json::json!({ "model_id": model_id }),
            )
            .await
    }

    /// Calls `tenzro_modelMetadata`: model metadata.
    pub async fn model_metadata(
        &self,
        model_id: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_modelMetadata",
                serde_json::json!({ "model_id": model_id }),
            )
            .await
    }

    /// Calls `tenzro_registerKeyRelease`: register a model's key-release policy: a KeyRelease transaction signed by the account that owns the policy.
    pub async fn register_key_release(
        &self,
        params: serde_json::Value,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc.call("tenzro_registerKeyRelease", params).await
    }

    /// Calls `tenzro_revokeKeyRelease`: revoke a model's key-release policy: a KeyRelease transaction signed by the account that owns the policy.
    pub async fn revoke_key_release(
        &self,
        params: serde_json::Value,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc.call("tenzro_revokeKeyRelease", params).await
    }

    /// Calls `tenzro_requestKeyRelease`: submit an attested environment's release request (`request`), which the provider node verifies and records.
    pub async fn request_key_release(
        &self,
        params: serde_json::Value,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc.call("tenzro_requestKeyRelease", params).await
    }

    /// Calls `tenzro_getKeyRelease`: a model's release policy and releases (`model_id`), or for a recorded `request` the content key sealed to the environment.
    pub async fn get_key_release(
        &self,
        params: serde_json::Value,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc.call("tenzro_getKeyRelease", params).await
    }

    /// Calls `tenzro_commitTrainingRound`: commit a training round's signed receipt against its milestone escrow.
    pub async fn commit_training_round(
        &self,
        params: serde_json::Value,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc.call("tenzro_commitTrainingRound", params).await
    }

    /// Calls `tenzro_settleTrainingRound`: settle a committed training round (`receipt_id`) once its challenge window has closed.
    pub async fn settle_training_round(
        &self,
        params: serde_json::Value,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc.call("tenzro_settleTrainingRound", params).await
    }

    /// Calls `tenzro_trainedModelProvenance`: the provenance of a trained model (`model_id`) from its committed training rounds (`rounds`).
    pub async fn trained_model_provenance(
        &self,
        params: serde_json::Value,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc.call("tenzro_trainedModelProvenance", params).await
    }

    /// Calls `tenzro_getToolCallRecords`: the tool-call records this node signed for an agent (`agent_did`, `limit`), and whether it records.
    pub async fn get_tool_call_records(
        &self,
        params: serde_json::Value,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc.call("tenzro_getToolCallRecords", params).await
    }

    /// Calls `tenzro_agentNodePqKey`: this node's ML-DSA-65 key for an agent (`agent_did`) and its proof of possession.
    pub async fn agent_node_pq_key(
        &self,
        params: serde_json::Value,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc.call("tenzro_agentNodePqKey", params).await
    }

    /// Calls `tenzro_getAttestationLog`: the node's attestation log,
    /// `{ head, entries }`.
    pub async fn get_attestation_log(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_getAttestationLog", serde_json::json!({}))
            .await
    }

    /// Calls `tenzro_moeListReceipts`: moe list receipts.
    pub async fn moe_list_receipts(
        &self,
        model_id: Option<&str>,
        limit: Option<u64>,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_moeListReceipts",
                serde_json::json!({ "model_id": model_id, "limit": limit }),
            )
            .await
    }
}
