//! Tenzro Network WASI 0.2 component host.
//!
//! Sandboxed, capability-based, deterministic runtime for executing
//! agent skills, MCP tools, and A2A skill components on a Tenzro node.
//!
//! - **Language-agnostic skills.** Components compile from Rust,
//!   TypeScript / JavaScript, Go, AssemblyScript, Python, and any other
//!   language with a WASI 0.2 target.
//! - **Capability-based sandbox.** A component starts with no filesystem,
//!   no network, no environment. Hosts grant capabilities explicitly via
//!   [`SkillCapabilities`].
//! - **Deterministic fuel accounting.** Wasmtime fuel metering produces
//!   reproducible cost reports independent of wall-clock time.
//! - **Cryptographic component identity.** Every loaded component is
//!   identified by its SHA-256 content hash. On-chain skill / tool
//!   registries pin exact bytes.

#![warn(missing_docs)]

pub mod capabilities;
pub mod engine;
pub mod error;
pub mod host;
pub mod manifest;
pub mod metrics;
pub mod runtime;

pub use capabilities::{NetworkCapability, SkillCapabilities, StorageCapability};
pub use engine::WasmEngine;
pub use error::{WasmError, WasmResult};
pub use host::{HostInterface, HostInvocation, InvocationResult};
pub use manifest::{ComponentManifest, ComponentRuntime};
pub use metrics::{ExecutionReceipt, FuelReport};
pub use runtime::{LoadedComponent, SkillRuntime};
