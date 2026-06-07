//! Host-interface plumbing — the contract a Tenzro node exposes to
//! WASI components.
//!
//! Components see two surfaces:
//!
//! 1. The standard WASI 0.2 worlds (cli, http, sockets, filesystem,
//!    clocks, random, ...). Gated by [`crate::SkillCapabilities`].
//! 2. Tenzro-native interfaces exported under the `tenzro:*`
//!    namespace — read a config value, publish an event, request an
//!    inference, sign a payment under a delegated scope, etc.
//!
//! Tenzro interfaces are not raw chain syscalls. Components do not get
//! direct access to validator signing keys or to the underlying VM
//! executors. Every call is mediated through a [`HostInterface`]
//! implementation supplied by the host process.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use crate::error::WasmResult;

/// A request from a guest component to a host-exported `tenzro:*`
/// method.
#[derive(Debug, Clone)]
pub struct HostInvocation {
    /// Fully-qualified method name, e.g. `wallet.read_balance`.
    pub method: String,

    /// Method arguments, encoded as JSON for forward-compatibility.
    pub args: Value,

    /// The DID of the agent (or anonymous-tool) that owns the
    /// component invocation. Hosts use this to enforce per-DID quotas,
    /// delegation scopes, and spending limits.
    pub caller_did: Option<String>,
}

/// Result returned from a host-exported `tenzro:*` method.
#[derive(Debug, Clone)]
pub struct InvocationResult {
    /// JSON payload returned to the guest. The guest decodes this
    /// against the component-model interface it imported.
    pub value: Value,

    /// Fuel cost the host charges for servicing this call. The runtime
    /// debits this from the component's fuel budget before returning
    /// control to the guest.
    pub fuel_cost: u64,
}

/// Trait the node (or agent-kit) implements to serve `tenzro:*` calls.
///
/// Implementations are responsible for:
///
/// - Enforcing the manifest's declared `host_methods` allow-list. The
///   runtime calls `is_method_allowed` before dispatching, so an
///   implementation can also enforce per-DID policy on top.
/// - Charging fuel for expensive host operations (DB reads, network
///   round-trips, inference) so a component cannot DoS the node by
///   chaining cheap-looking host calls.
/// - Returning structured errors via `WasmResult` so the runtime can
///   surface them through `WasmError::HostContractViolation`.
#[async_trait]
pub trait HostInterface: Send + Sync + 'static {
    /// Returns `true` if the host policy permits `caller_did` to invoke
    /// `method`. Called once per invocation; the runtime short-circuits
    /// a `false` result into [`crate::WasmError::MissingCapability`].
    fn is_method_allowed(&self, method: &str, caller_did: Option<&str>) -> bool;

    /// Dispatches a host call.
    async fn dispatch(&self, invocation: HostInvocation) -> WasmResult<InvocationResult>;
}

/// Convenience alias for shared host interface handles.
pub type SharedHost = Arc<dyn HostInterface>;

/// A no-op host that denies everything. Useful in unit tests and as a
/// safety default when no host has been wired yet.
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyAllHost;

#[async_trait]
impl HostInterface for DenyAllHost {
    fn is_method_allowed(&self, _method: &str, _caller_did: Option<&str>) -> bool {
        false
    }

    async fn dispatch(&self, invocation: HostInvocation) -> WasmResult<InvocationResult> {
        Err(crate::error::WasmError::MissingCapability(format!(
            "host method '{}' denied by DenyAllHost",
            invocation.method
        )))
    }
}
