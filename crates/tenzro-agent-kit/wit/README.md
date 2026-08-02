# Tenzro WIT Registry

WebAssembly Interface Type definitions for components hosted by
`tenzro-wasm`. Each file pins a `package@version` so the host can dispatch
the correct world per component type.

| File | Package | World | Used by |
|---|---|---|---|
| `tenzro-skill.wit` | `tenzro:skill@1.0.0` | `tenzro-skill-world` | Skill components (`builtin://*`, paid marketplace skills) |
| `tenzro-mcp-tool.wit` | `tenzro:mcp-tool@1.0.0` | `tenzro-mcp-tool-world` | MCP tool components |
| `tenzro-a2a-skill.wit` | `tenzro:a2a-skill@1.0.0` | `tenzro-a2a-skill-world` | A2A skill components |

## Conventions

- Package versions follow semver-compatible major bumps when an existing
  function signature changes. Components must declare the same version
  the host advertises; the host rejects loads on mismatch.
- All worlds import the WASI 0.2.9 base — same baseline as the
  `tenzro-wasm` engine. WASI 0.3 (async) lands in a separate `@2.0`
  package set once upstream stabilises.
- WIT is the source of truth. The host's bindgen-generated Rust types
  are derived from these files; regenerate when editing.

## Versioning + the agent-kit module surface

`tenzro-agent-kit::wasm` consumes these files via `wit_bindgen_rust`
macros against `wit/`. Components targeting Tenzro must compile with the
matching package version (e.g. `wit-bindgen 0.55` aligns with the
`@0.2.9` WASI base in Wasmtime 27).
