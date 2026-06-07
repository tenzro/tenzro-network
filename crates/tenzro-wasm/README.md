# tenzro-wasm

WASI 0.2 component host for Tenzro Network — a sandboxed, capability-based,
deterministic runtime for executing community-supplied **agent skills**,
**MCP tools**, and **A2A skill components** on a Tenzro node.

## What this enables

- **Language-agnostic skills.** Components compile from Rust, TypeScript /
  JavaScript, Go, AssemblyScript, Python, and any other language with a
  WASI 0.2 target.
- **Capability-based sandbox.** A component starts with no filesystem,
  no network, no environment. Hosts grant capabilities explicitly through
  the manifest's `capabilities` block.
- **Deterministic fuel accounting.** Wasmtime fuel metering produces
  reproducible cost reports independent of wall-clock time.
- **Cryptographic component identity.** Every loaded component is
  identified by its SHA-256 content hash. On-chain skill / tool
  registries pin exact bytes; manifests with a wrong hash are rejected
  at load.
- **Execution receipts.** Each invocation returns an `ExecutionReceipt`
  the host can chain into Tenzro `ReceiptEnvelope` records for durable,
  auditable execution history.

## Public surface

```text
WasmEngine               process-wide Wasmtime engine
SkillRuntime             per-host runtime, holds a component registry
ComponentManifest        declarative metadata bundled with each .wasm
SkillCapabilities        sandbox grants (storage, network, host methods)
HostInterface (trait)    node-side dispatcher for `tenzro:*` calls
ExecutionReceipt         result of an invocation
```

Hosts integrate by:

1. Constructing one `WasmEngine` for the process.
2. Constructing one `SkillRuntime` per `(engine, host_interface)` pair.
3. Calling `runtime.register_component(manifest, bytes)` for every
   component the host serves.
4. Calling `runtime.invoke(component_id, function, input, caller_did)`
   to run an exported function.

## Where this is wired

- `crates/tenzro-agent-kit` — alternative skill-execution runtime,
  selected when a skill template's manifest declares
  `runtime: agent-skill`.
- `crates/tenzro-node` — MCP tool host. Community-submitted MCP tools
  ship as `.wasm` components; the node executes them in-process with
  capability checks.

## Security defaults

- All capability lists default to deny.
- The `WasmEngine` is configured with `wasm_reference_types(false)` and
  `wasm_relaxed_simd(false)` for deterministic behavior across
  Wasmtime versions.
- Fuel metering and epoch interruption are both on by default.
