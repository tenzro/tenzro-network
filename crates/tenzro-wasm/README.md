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

## Modules

| Module | Role |
|---|---|
| `engine` | `WasmEngine` — the process-wide Wasmtime engine. Components compile once against it and instantiate cheaply many times; a node holds one `Arc<WasmEngine>` shared by the agent-kit skill executor and the MCP tool host. |
| `manifest` | `ComponentManifest` / `ComponentRuntime` — the declarative metadata bundled with each `.wasm`, including the content hash the runtime checks at registration. |
| `capabilities` | `SkillCapabilities`, `StorageCapability`, `NetworkCapability` — the grant set a manifest declares, translated into a WASI 0.2 context at instantiation. |
| `wasi_state` | `WasiState` — the per-invocation `Store<T>` data carrying the WASI 0.2 context, the WASI HTTP context, and the component-model resource table. Built from the manifest's capabilities, so a component starts with no ambient authority. |
| `host` | `HostInterface`, `HostInvocation`, `InvocationResult`, `SharedHost` — the node-side dispatcher for `tenzro:*` calls made from inside a component. |
| `runtime` | `SkillRuntime`, `LoadedComponent` — the embed-friendly entry point: register a component, invoke an export, get a receipt. |
| `http` | `HttpComponent`, `FunctionResponse`, `IncomingBody`, `OutgoingBody`, `Scheme` — the `wasi:http` serving path for `function`-class apps. A component exporting the `wasi:http/proxy` world is pre-linked once, then serves one request per `serve` call. Bodies are `hyper` 1.x types, so the node's axum edge hands a decoded request straight through and streams the response back over the `tenzro/http` bi-stream without a second serialization hop. |
| `metrics` | `FuelReport` and `ExecutionReceipt` — fuel accounting and the signed record of an invocation. |
| `error` | `WasmError` and `WasmResult`. |

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
  are `.wasm` components; the node executes them in-process with
  capability checks. The node's app-hosting path uses `HttpComponent`
  to serve `function`-class apps over the `wasi:http/proxy` world.

## Security defaults

- All capability lists default to deny.
- The `WasmEngine` is configured with `wasm_reference_types(false)` and
  `wasm_relaxed_simd(false)` for deterministic behavior across
  Wasmtime versions.
- Fuel metering and epoch interruption are both on by default.
