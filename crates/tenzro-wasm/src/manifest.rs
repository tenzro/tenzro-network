//! Component manifest types — declarative metadata bundled with each
//! `.wasm` component.
//!
//! A manifest is a small JSON document that travels alongside the
//! component bytes. It declares the component's identity, the runtime
//! ABI it targets, the host interfaces it depends on, and the
//! capabilities it requests. The host validates the manifest at load
//! time and refuses to instantiate components whose declared
//! capabilities exceed what the host policy permits.

use serde::{Deserialize, Serialize};

use crate::capabilities::SkillCapabilities;

/// Component runtime ABIs the host knows how to instantiate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComponentRuntime {
    /// WASI 0.2 component-model targeting the standard CLI world plus
    /// the Tenzro host-exported `tenzro:*` interfaces.
    WasiComponent,

    /// A skill component — same ABI as [`Self::WasiComponent`] but
    /// loaded by the agent-kit executor rather than the MCP host.
    AgentSkill,

    /// An MCP tool component — same ABI as [`Self::WasiComponent`] but
    /// the host wires the component's exports to the MCP tool registry
    /// instead of the agent-kit dispatcher.
    McpTool,
}

impl ComponentRuntime {
    /// Parse the manifest's `runtime` field. Returns `None` for
    /// unrecognized values so the caller can produce a
    /// `WasmError::UnsupportedRuntime`.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "wasi-component" => Some(Self::WasiComponent),
            "agent-skill" => Some(Self::AgentSkill),
            "mcp-tool" => Some(Self::McpTool),
            _ => None,
        }
    }
}

/// Declarative manifest for a `.wasm` component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentManifest {
    /// Stable component identifier. Skill / tool registries pin this.
    pub id: String,

    /// SemVer string for the component itself (not the SDK).
    pub version: String,

    /// Lowercase hex of the SHA-256 of the component bytes. The host
    /// verifies this at load time; a mismatch is rejected as a
    /// `WasmError::InvalidComponent`.
    pub content_hash_hex: String,

    /// Runtime ABI the component targets.
    pub runtime: ComponentRuntime,

    /// Capabilities the component requests.
    #[serde(default)]
    pub capabilities: SkillCapabilities,

    /// Wall-clock execution deadline in milliseconds. The host enforces
    /// this via Wasmtime epoch interruption. `None` means "use the
    /// host default."
    #[serde(default)]
    pub deadline_ms: Option<u64>,

    /// Initial fuel budget. The host enforces this via Wasmtime's fuel
    /// metering. `None` means "use the host default."
    #[serde(default)]
    pub fuel_limit: Option<u64>,

    /// Human-readable description (for skill/tool marketplaces).
    #[serde(default)]
    pub description: Option<String>,

    /// Optional creator DID (for the paid-marketplace 5% commission flow).
    #[serde(default)]
    pub creator_did: Option<String>,
}

impl ComponentManifest {
    /// Returns the manifest's runtime as a string suitable for logging
    /// or error messages.
    pub fn runtime_str(&self) -> &'static str {
        match self.runtime {
            ComponentRuntime::WasiComponent => "wasi-component",
            ComponentRuntime::AgentSkill => "agent-skill",
            ComponentRuntime::McpTool => "mcp-tool",
        }
    }
}
