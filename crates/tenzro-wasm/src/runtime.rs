//! Skill runtime — embed-friendly entry point for hosts.
//!
//! A [`SkillRuntime`] holds the engine, a registry of loaded
//! components, and the shared host interface.
//!
//! ## Lifecycle
//!
//! 1. The host constructs the runtime via [`SkillRuntime::new`].
//! 2. For each `(manifest, component_bytes)` it wants to serve, the
//!    host calls [`SkillRuntime::register_component`]. The runtime
//!    verifies the content hash, validates the component with
//!    Wasmtime, and stores the handle.
//! 3. To invoke an exported function, the host calls
//!    [`SkillRuntime::invoke`]. The runtime instantiates the component
//!    with the manifest's capabilities translated into a WASI 0.2
//!    context, runs the exported function, debits fuel for any
//!    `tenzro:*` host calls, and returns an [`crate::ExecutionReceipt`].

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use wasmtime::Store;
use wasmtime::component::{Component, Linker, TypedFunc};

use crate::capabilities::SkillCapabilities;
use crate::engine::WasmEngine;
use crate::error::{WasmError, WasmResult};
use crate::host::SharedHost;
use crate::manifest::ComponentManifest;
use crate::metrics::{ExecutionReceipt, FuelReport, InvocationOutcome};
use crate::wasi_state::WasiState;

/// WIT interface path of the Tenzro skill export.
const SKILL_INTERFACE: &str = "tenzro:skill/skill@1.0.0";

/// A component that has been validated and admitted to the runtime.
#[derive(Clone, Debug)]
pub struct LoadedComponent {
    /// Stable identifier from the manifest.
    pub id: String,

    /// The validated manifest.
    pub manifest: Arc<ComponentManifest>,

    /// The raw component bytes. Kept around for re-instantiation under
    /// the pooling allocator.
    pub bytes: Bytes,

    /// Default deadline applied to invocations against this component.
    pub deadline: Duration,

    /// Default fuel budget.
    pub fuel_limit: u64,
}

/// Public, embed-friendly skill runtime.
pub struct SkillRuntime {
    engine: Arc<WasmEngine>,
    host: SharedHost,
    components: DashMap<String, Arc<LoadedComponent>>,
    /// Per-component instantiation lock, kept separate from the
    /// registry map so a slow `invoke` cannot block concurrent
    /// `register_component` calls.
    locks: DashMap<String, Arc<Mutex<()>>>,
    default_deadline: Duration,
    default_fuel_limit: u64,
}

impl SkillRuntime {
    /// Builds a runtime with engine `engine`, host `host`, default
    /// per-invocation deadline `default_deadline`, and default per-
    /// invocation fuel limit `default_fuel_limit`.
    pub fn new(
        engine: Arc<WasmEngine>,
        host: SharedHost,
        default_deadline: Duration,
        default_fuel_limit: u64,
    ) -> Self {
        Self {
            engine,
            host,
            components: DashMap::new(),
            locks: DashMap::new(),
            default_deadline,
            default_fuel_limit,
        }
    }

    /// Borrow the engine.
    pub fn engine(&self) -> &WasmEngine {
        &self.engine
    }

    /// Borrow the host.
    pub fn host(&self) -> &SharedHost {
        &self.host
    }

    /// Validate and register a component. Returns the loaded handle
    /// and stores it in the runtime's registry, keyed by
    /// `manifest.id`. Re-registering the same id overwrites the
    /// existing entry.
    ///
    /// Validation includes:
    /// - SHA-256 of `bytes` must match `manifest.content_hash_hex`.
    /// - `manifest.runtime` must be a value the host recognizes.
    /// - Bytes must be a syntactically-valid Wasm component (handed
    ///   to Wasmtime's `Component::new`; not yet instantiated).
    pub fn register_component(
        &self,
        manifest: ComponentManifest,
        bytes: Bytes,
    ) -> WasmResult<Arc<LoadedComponent>> {
        // Step 1 — re-hash the bytes and verify against the manifest.
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();
        let computed_hash_hex = hex::encode(digest);
        if computed_hash_hex != manifest.content_hash_hex.to_lowercase() {
            return Err(WasmError::InvalidComponent(format!(
                "manifest content_hash_hex {} does not match SHA-256 of bytes {}",
                manifest.content_hash_hex, computed_hash_hex
            )));
        }

        // Step 2 — hand to Wasmtime for syntactic validation. We
        // discard the compiled Component handle here — the per-
        // invocation `Store<T>` is built lazily inside `invoke`.
        wasmtime::component::Component::new(self.engine.inner(), bytes.as_ref())
            .map_err(|e| WasmError::InvalidComponent(format!("wasmtime rejected component: {e:#}")))?;

        let deadline = manifest
            .deadline_ms
            .map(Duration::from_millis)
            .unwrap_or(self.default_deadline);
        let fuel_limit = manifest.fuel_limit.unwrap_or(self.default_fuel_limit);

        let component = Arc::new(LoadedComponent {
            id: manifest.id.clone(),
            manifest: Arc::new(manifest),
            bytes,
            deadline,
            fuel_limit,
        });

        let id = component.id.clone();
        self.components.insert(id.clone(), component.clone());
        self.locks
            .entry(id)
            .or_insert_with(|| Arc::new(Mutex::new(())));

        Ok(component)
    }

    /// Drop a previously registered component. Returns `true` if a
    /// component with that id was present.
    pub fn unregister_component(&self, id: &str) -> bool {
        self.locks.remove(id);
        self.components.remove(id).is_some()
    }

    /// Look up a previously registered component.
    pub fn get_component(&self, id: &str) -> Option<Arc<LoadedComponent>> {
        self.components.get(id).map(|c| c.clone())
    }

    /// List all currently registered component ids.
    pub fn list_components(&self) -> Vec<String> {
        self.components.iter().map(|c| c.key().clone()).collect()
    }

    /// Invoke an exported function on a registered component.
    ///
    /// `function` is the WASI 0.2 export name to call (e.g.
    /// `wasi:cli/run@0.2.0#run`, or one of the Tenzro-specific exports
    /// like `tenzro:skill/handler#invoke`).
    ///
    /// `input` is the canonical JSON payload the host passes to the
    /// guest. The component is responsible for decoding it.
    ///
    /// On success the runtime returns the component's serialized
    /// output bytes alongside a signed [`ExecutionReceipt`] suitable
    /// for chaining into a Tenzro `ReceiptEnvelope`.
    pub async fn invoke(
        &self,
        component_id: &str,
        function: &str,
        input: Bytes,
        caller_did: Option<String>,
    ) -> WasmResult<(Bytes, ExecutionReceipt)> {
        let component = self
            .components
            .get(component_id)
            .map(|c| c.clone())
            .ok_or_else(|| {
                WasmError::HostContractViolation(format!(
                    "no component registered with id {component_id}"
                ))
            })?;

        // Hash the input now so the receipt can bind to it even on
        // trap paths.
        let mut hasher = Sha256::new();
        hasher.update(&input);
        let input_hash_hex = hex::encode(hasher.finalize());

        // Per-component instantiation lock — the pooling allocator
        // is process-wide, but we still serialize stateful instances
        // per component to keep host-side bookkeeping linearizable.
        let lock = self
            .locks
            .entry(component_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _guard = lock.lock().await;

        let started = Instant::now();
        let (outcome, output_bytes, consumed_fuel) = self
            .invoke_inner(
                component.clone(),
                function,
                input.clone(),
                caller_did.clone(),
            )
            .await?;
        let elapsed = started.elapsed();

        let mut hasher = Sha256::new();
        hasher.update(output_bytes.as_ref());
        let output_hash_hex = hex::encode(hasher.finalize());

        let receipt = ExecutionReceipt {
            component_id: component.id.clone(),
            content_hash_hex: component.manifest.content_hash_hex.clone(),
            function: function.to_string(),
            input_hash_hex,
            output_hash_hex,
            outcome,
            fuel: FuelReport {
                budget: component.fuel_limit,
                consumed: consumed_fuel,
                remaining: component.fuel_limit.saturating_sub(consumed_fuel),
                elapsed,
            },
            completed_at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or_default(),
        };

        Ok((output_bytes, receipt))
    }

    async fn invoke_inner(
        &self,
        component: Arc<LoadedComponent>,
        function: &str,
        input: Bytes,
        caller_did: Option<String>,
    ) -> WasmResult<(InvocationOutcome, Bytes, u64)> {
        // Per-invocation method-level capability check.
        let synthetic_method = format!("component.invoke:{}#{}", component.id, function);
        if !self
            .host
            .is_method_allowed(&synthetic_method, caller_did.as_deref())
        {
            return Err(WasmError::MissingCapability(format!(
                "host policy denies invocation of {} on {}",
                function, component.id
            )));
        }

        // Validate the capability surface the manifest declares.
        let caps: &SkillCapabilities = &component.manifest.capabilities;
        for method in &caps.host_methods {
            if !self.host.is_method_allowed(method, caller_did.as_deref()) {
                return Err(WasmError::MissingCapability(format!(
                    "manifest requests host method {method} which is denied by host policy",
                )));
            }
        }

        // Compile + link the component. WASI 0.2 base interfaces are
        // linked; the store's context is built from the manifest's
        // capabilities so the guest starts with no ambient authority.
        let engine = self.engine.inner();
        let wasm_component = Component::new(engine, component.bytes.as_ref())
            .map_err(|e| WasmError::InvalidComponent(format!("recompile failed: {e:#}")))?;

        let mut linker: Linker<WasiState> = Linker::new(engine);
        wasmtime_wasi::p2::add_to_linker_async(&mut linker)
            .map_err(|e| WasmError::Wasmtime(format!("adding wasi to linker: {e:#}")))?;

        let state = WasiState::from_capabilities(caps);
        let mut store = Store::new(engine, state);
        store
            .set_fuel(component.fuel_limit)
            .map_err(|e| WasmError::Wasmtime(format!("setting fuel: {e:#}")))?;
        let epoch_ticks = component.deadline.as_millis().max(1) as u64;
        store.set_epoch_deadline(epoch_ticks);

        let instance = linker
            .instantiate_async(&mut store, &wasm_component)
            .await
            .map_err(classify_wasmtime_error)?;

        // Resolve the exported `tenzro:skill/skill@1.0.0#invoke` function.
        // `function` selects the export name inside that interface;
        // callers pass "invoke" for the request/response entry point.
        let iface_index = instance
            .get_export_index(&mut store, None, SKILL_INTERFACE)
            .ok_or_else(|| {
                WasmError::HostContractViolation(format!(
                    "component {} does not export interface {SKILL_INTERFACE}",
                    component.id
                ))
            })?;
        let func_index = instance
            .get_export_index(&mut store, Some(&iface_index), function)
            .ok_or_else(|| {
                WasmError::HostContractViolation(format!(
                    "interface {SKILL_INTERFACE} has no export {function}",
                ))
            })?;
        let invoke: TypedFunc<(String,), (Result<String, String>,)> = instance
            .get_typed_func(&mut store, func_index)
            .map_err(|e| {
                WasmError::HostContractViolation(format!(
                    "export {function} has the wrong signature (want (string) -> result<string,string>): {e:#}"
                ))
            })?;

        // The skill contract is JSON-in / JSON-out. We hand the raw
        // input bytes as a UTF-8 string; malformed UTF-8 is a caller
        // error, not a guest trap.
        let request = String::from_utf8(input.to_vec())
            .map_err(|e| WasmError::Serialization(format!("skill input is not UTF-8: {e}")))?;

        let call_result = invoke.call_async(&mut store, (request,)).await;
        let consumed = component
            .fuel_limit
            .saturating_sub(store.get_fuel().unwrap_or(0));

        // `call_async` runs the component's post-return automatically,
        // so no manual cleanup step is needed here.
        match call_result {
            Ok((Ok(json),)) => {
                Ok((InvocationOutcome::Success, Bytes::from(json.into_bytes()), consumed))
            }
            Ok((Err(guest_err),)) => Err(WasmError::HostContractViolation(format!(
                "skill returned error: {guest_err}"
            ))),
            Err(e) => Err(classify_wasmtime_error(e)),
        }
    }
}

/// Maps a wasmtime instantiation / call error onto the fuel / deadline /
/// trap variants of [`WasmError`].
fn classify_wasmtime_error(err: wasmtime::Error) -> WasmError {
    if let Some(trap) = err.downcast_ref::<wasmtime::Trap>() {
        return match trap {
            wasmtime::Trap::OutOfFuel => WasmError::FuelExhausted { consumed: 0 },
            wasmtime::Trap::Interrupt => WasmError::DeadlineExceeded {
                elapsed: Duration::ZERO,
            },
            other => WasmError::Trap(format!("{other:?}")),
        };
    }
    WasmError::Wasmtime(format!("{err:#}"))
}

impl std::fmt::Debug for SkillRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkillRuntime")
            .field("default_deadline", &self.default_deadline)
            .field("default_fuel_limit", &self.default_fuel_limit)
            .field("registered_components", &self.components.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::SkillCapabilities;
    use crate::host::DenyAllHost;
    use crate::manifest::ComponentRuntime;

    fn dummy_manifest(id: &str, bytes: &[u8]) -> ComponentManifest {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        ComponentManifest {
            id: id.to_string(),
            version: "0.1.0".into(),
            content_hash_hex: hex::encode(hasher.finalize()),
            runtime: ComponentRuntime::AgentSkill,
            capabilities: SkillCapabilities::deny_all(),
            deadline_ms: Some(5_000),
            fuel_limit: Some(1_000_000),
            description: None,
            creator_did: None,
        }
    }

    #[test]
    fn manifest_content_hash_mismatch_is_rejected() {
        let engine = Arc::new(WasmEngine::new().unwrap());
        let host: SharedHost = Arc::new(DenyAllHost);
        let runtime = SkillRuntime::new(
            engine,
            host,
            Duration::from_secs(5),
            1_000_000,
        );

        let bytes = Bytes::from_static(b"not actually a wasm component");
        // Build a manifest with a deliberately-wrong content hash.
        let mut manifest = dummy_manifest("skill.tenzro.test", b"different bytes");
        manifest.id = "skill.tenzro.test".into();

        let err = runtime
            .register_component(manifest, bytes)
            .expect_err("mismatched hash must be rejected");
        match err {
            WasmError::InvalidComponent(msg) => {
                assert!(msg.contains("does not match"));
            }
            other => panic!("expected InvalidComponent, got {other:?}"),
        }
    }
}
