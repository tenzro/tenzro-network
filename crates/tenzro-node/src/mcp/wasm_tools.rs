//! Sandboxed WASI 0.2 component host for community-supplied MCP tools.
//!
//! Compiled only when the node is built with `--features wasi-skills`.
//!
//! Tools are registered as `(ComponentManifest, Bytes)` pairs and
//! dispatched through `tenzro_wasm::SkillRuntime`. Every invocation is
//! capability-checked against the manifest's `host_methods` allow-list
//! and the host policy resolved from the caller's DID.
//!
//! The runtime exposes three entry points the MCP server uses:
//!
//! - [`SandboxedToolRegistry::register`] — admit a `.wasm` component.
//! - [`SandboxedToolRegistry::invoke`] — dispatch an MCP tool call.
//! - [`SandboxedToolRegistry::list`] — enumerate active components.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use serde_json::Value;
use tenzro_wasm::{
    ComponentManifest, ExecutionReceipt, HostInterface, HostInvocation, InvocationResult,
    SharedHost, SkillRuntime, WasmEngine, WasmResult,
};
use tracing::warn;

/// Host policy used by the MCP-side sandboxed tool runtime. Allows any
/// method whose name starts with `mcp.public.` (the public read tier).
/// Replace with a richer implementation when the MCP server's auth and
/// quota plumbing is wired up.
#[derive(Default)]
pub struct McpToolHost;

#[async_trait]
impl HostInterface for McpToolHost {
    fn is_method_allowed(&self, method: &str, _caller_did: Option<&str>) -> bool {
        method.starts_with("mcp.public.")
            || method.starts_with("config.read")
            || method.starts_with("metrics.observe")
            || method.starts_with("events.publish")
            || method.starts_with("component.invoke:")
    }

    async fn dispatch(&self, invocation: HostInvocation) -> WasmResult<InvocationResult> {
        warn!(
            method = %invocation.method,
            caller_did = ?invocation.caller_did,
            "McpToolHost::dispatch — placeholder host returns empty result",
        );
        Ok(InvocationResult {
            value: Value::Null,
            fuel_cost: 0,
        })
    }
}

/// Sandboxed MCP tool registry. One per MCP server instance.
#[derive(Clone)]
pub struct SandboxedToolRegistry {
    inner: Arc<SkillRuntime>,
}

impl SandboxedToolRegistry {
    /// Build a new registry. The supplied [`SharedHost`] is the policy
    /// gate for every `tenzro:*` host call made from a component.
    pub fn new(host: SharedHost) -> WasmResult<Self> {
        let engine = Arc::new(WasmEngine::new()?);
        let runtime =
            SkillRuntime::new(engine, host, std::time::Duration::from_secs(10), 50_000_000);
        Ok(Self {
            inner: Arc::new(runtime),
        })
    }

    /// Convenience constructor that wires the registry to the default
    /// [`McpToolHost`] policy.
    pub fn with_default_host() -> WasmResult<Self> {
        Self::new(Arc::new(McpToolHost))
    }

    /// Register a `.wasm` tool component. Returns the component id from
    /// the manifest.
    pub fn register(&self, manifest: ComponentManifest, bytes: Bytes) -> WasmResult<String> {
        let loaded = self.inner.register_component(manifest, bytes)?;
        Ok(loaded.id.clone())
    }

    /// Drop a previously registered component.
    pub fn unregister(&self, component_id: &str) -> bool {
        self.inner.unregister_component(component_id)
    }

    /// Dispatch an MCP tool call. `function` is the exported function
    /// name on the component; `caller_did` is the DID of the agent or
    /// operator the call is being attributed to.
    pub async fn invoke(
        &self,
        component_id: &str,
        function: &str,
        input: Bytes,
        caller_did: Option<String>,
    ) -> WasmResult<(Bytes, ExecutionReceipt)> {
        self.inner
            .invoke(component_id, function, input, caller_did)
            .await
    }

    /// List currently registered components.
    pub fn list(&self) -> Vec<String> {
        self.inner.list_components()
    }
}

impl std::fmt::Debug for SandboxedToolRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxedToolRegistry")
            .finish_non_exhaustive()
    }
}
