//! WASI 0.2 sandboxed skill runtime adapter.
//!
//! Wires `tenzro-wasm::SkillRuntime` into the agent-kit executor so a
//! `SkillTemplate` whose manifest declares `runtime: "agent-skill"` is
//! dispatched through the sandboxed component runtime instead of the
//! native Rust or Python skill paths.
//!
//! Compiled only when the crate is built with `--features wasi-skills`.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tenzro_wasm::{
    ComponentManifest, ExecutionReceipt, SharedHost, SkillRuntime, WasmEngine, WasmError, WasmResult,
};

/// Default per-invocation deadline if a skill manifest does not specify one.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(10);

/// Default fuel budget if a skill manifest does not specify one.
/// Sized so a typical embedding / scoring / classification skill returns
/// in well under one second on a modern CPU.
pub const DEFAULT_FUEL_LIMIT: u64 = 50_000_000;

/// Sandboxed skill runtime owned by an [`crate::AgentKit`] instance.
///
/// The runtime is constructed once at AgentKit startup and shared by
/// reference across spawned agents.
#[derive(Clone)]
pub struct WasmSkillRuntime {
    inner: Arc<SkillRuntime>,
}

impl WasmSkillRuntime {
    /// Build a new sandboxed skill runtime with the supplied host
    /// interface implementation.
    pub fn new(host: SharedHost) -> WasmResult<Self> {
        let engine = Arc::new(WasmEngine::new()?);
        let runtime = SkillRuntime::new(engine, host, DEFAULT_DEADLINE, DEFAULT_FUEL_LIMIT);
        Ok(Self {
            inner: Arc::new(runtime),
        })
    }

    /// Register a `.wasm` component under its manifest. Returns the
    /// stored component id on success.
    pub fn register(&self, manifest: ComponentManifest, bytes: Bytes) -> WasmResult<String> {
        let loaded = self.inner.register_component(manifest, bytes)?;
        Ok(loaded.id.clone())
    }

    /// Dispatch an invocation. The `caller_did` is the spawning agent's
    /// machine DID so the host can enforce per-DID quotas + spending limits.
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

    /// Drop a previously registered component.
    pub fn unregister(&self, component_id: &str) -> bool {
        self.inner.unregister_component(component_id)
    }

    /// List currently registered components.
    pub fn list(&self) -> Vec<String> {
        self.inner.list_components()
    }
}

/// Convert any [`WasmError`] into the agent-kit's error type.
impl From<WasmError> for crate::error::AgentKitError {
    fn from(err: WasmError) -> Self {
        crate::error::AgentKitError::ExecutionFailed(err.to_string())
    }
}
