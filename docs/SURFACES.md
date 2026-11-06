# Client Surfaces

Every capability a Tenzro node has is reachable from every client surface. This
document says what those surfaces are, how that guarantee is maintained, and
what it does _not_ mean.

## The nine surfaces

| Surface        | Transport   | Discovery                    | Call by name              |
| -------------- | ----------- | ---------------------------- | ------------------------- |
| JSON-RPC       | `:8545`     | `tenzro_listRpcMethods`      | the method itself         |
| REST           | `:8545`     | `GET /rpc`                   | `POST /rpc/{method}`      |
| MCP            | `:3001/mcp` | `list_rpc_methods` tool      | `call_rpc` tool           |
| A2A            | `:3002`     | `rpc-gateway` skill          | `rpc-gateway` skill       |
| Rust SDK       | —           | `client.gateway().methods()` | `client.gateway().call()` |
| TypeScript SDK | —           | `client.gateway.methods()`   | `client.gateway.call()`   |
| Python SDK     | —           | `client.list_rpc_methods()`  | `client.call()`           |
| CLI            | —           | `tenzro rpc methods`         | `tenzro rpc call`         |
| OpenClaw       | —           | `list_rpc_methods()`         | `call_rpc()`              |

## How the guarantee holds

There is exactly one list of methods: `ADMIN_METHODS`, `OWNER_METHODS` and
`OPEN_METHODS` in `crates/tenzro-node/src/rpc_gates.rs`. The classification
test refuses to pass while any dispatch arm is missing from it, so that list
is the method surface rather than a copy of it. Two guarantees are built on it.

**Every method is reachable by name.** Each surface's discovery reads the list
at runtime, so none ships a hand-maintained directory that can drift, and a
client talking to a node newer than itself simply sees more.
`crates/tenzro-node/tests/surface_parity_integration.rs` asserts that the
directory reports every served method, that each surface ships both discovery
and a by-name call, and that the REST gateway is actually mounted.

**Every method has a named binding.** `crates/tenzro-types/tests/rpc_wiring.rs`
requires each dispatched method to be called by name from the CLI, the MCP
tools, the TypeScript SDK, the Rust SDK and the Python SDK. A method with no
client binding (the Ethereum and Solana JSON-RPC namespaces, served to EVM and
Solana wallets) is listed in `NODE_INTERNAL` with the reason, and a method left
off one surface is listed in `SURFACE_EXEMPT` with the reason and the surface.
A new RPC method therefore fails the build until it is wired everywhere.

## Named bindings and the gateway

The named bindings carry real signatures, documentation and types: what the
node takes and returns, checked against the handler and exercised by each
SDK's tests against a mocked node. The gateway is the floor beneath them: it
reaches a method a client release predates, and it is how a tool caller
explores the surface.

| SDK        | Package                 | Client                                     | Typed bindings                                                                 | By name                    |
| ---------- | ----------------------- | ------------------------------------------ | ------------------------------------------------------------------------------ | -------------------------- |
| TypeScript | `tenzro-sdk` (npm)      | `connectToNetwork()`, `new TenzroClient()` | one client per area (`client.wallet`, `client.inference`, `client.settle`, ...) | `client.gateway.call()`    |
| Rust       | `tenzro-sdk` (crates)   | `network::connect_to_network()`, `TenzroClient::new()` | one client per area (`client.wallet()`, `client.inference()`, ...)  | `client.gateway().call()`  |
| Python     | `tenzro` (PyPI)         | `RpcClient`, `AsyncRpcClient`              | one method per RPC method, generated from the method table, plus subpackages  | `client.call()`            |

The MCP server carries 403 tools: 248 typed tools with their own input schema
and 155 mirror tools that forward a `params` object to one method (see
[MCP.md](MCP.md)). Adding a tool per method is deliberately not the rule there:
tool-selection accuracy falls as the list grows, so methods without a typed
tool are reached through `call_rpc`.

## The gateway widens ergonomics, not authorization

A call through any gateway runs through the same dispatcher entry point as a
direct JSON-RPC request, behind:

1. the node's **access policy**, for the gateway's own surface,
2. the **default-deny classification** — a method nobody classified is refused
   before dispatch, and
3. the **handler's own principal check**. An open method that acts for someone
   takes that someone from a credential it can verify, never from a parameter:
   a paid tool, skill or workflow invocation is authorized and charged against
   the caller's DPoP-bound bearer, and a mutation of an identity, a delegation
   scope, an approval or a registry entry requires a DID envelope signed by the
   key that owns it. A payer, owner or approver named in the params is ignored.

A method a caller could not reach on `:8545` is a method they cannot reach
through any gateway. The parity tests assert this directly: an admin method
from a caller who is not an administrator is refused, a files method from a
caller the policy does not admit is refused, and an unclassified method is 404.

One thing does change, and it is worth stating rather than discovering. An
operator exposing MCP but not JSON-RPC has been relying on the MCP tool list as
a de-facto allowlist. After this, MCP reaches what the gates allow rather than
what someone remembered to write a tool for. That is intended — a tool list is
not an authorization model, and treating it as one meant the real gate was never
the one being reasoned about — but an operator wanting a narrower surface should
use the access policy's per-surface rules, which are the mechanism designed for
it.

## Discovery output

`tenzro_listRpcMethods` takes optional `namespace` and `contains` filters; the
unfiltered directory has one row per method the node dispatches. Each entry carries the gate class and the
method class the access policy decides it under, so a caller can tell what it
needs without provoking the error first:

```
$ tenzro rpc methods --contains Escrow
  Matched               3 of 447 served

  …
```

## Body ceilings are per-tier, and the JSON-RPC root is not the JSON tier

A request body limit cannot be raised by an inner layer underneath a smaller
outer one, so the ceilings are applied per sub-router rather than globally.
There are three tiers:

| Tier  | Ceiling | Routes                                                                                                                                                            |
| ----- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| JSON  | 2 MB    | `/health`, `/v1/models`, `/tenzro/generation`, the files and database routes, the gateway, and the generation routes whose bodies are a prompt or a numeric series    |
| Media | 64 MB   | `/v1/embeddings`, the Tenzro-namespaced detection / segmentation / video-embedding routes — **and the JSON-RPC root, `POST /`** |
| Audio | 128 MB  | `/v1/audio/transcriptions`, `/v1/audio/speech`                                                                                                                    |

The third row of the media tier is the one worth reading twice. `POST /` is the
JSON-RPC endpoint, and its name says JSON, but several methods dispatched there
carry base64 media by design:

- `tenzro_mediaGen_render` — an editing render's conditioning images

The JSON-RPC root is therefore mounted in its own tier at the media ceiling
for the operator.

Two consequences to keep in mind when adding an RPC method:

- The ceiling is per-surface, not per-method. Raising the root to 64 MB raised
  it for every JSON-RPC method, not only the media-carrying ones. That is the
  cost of a single-endpoint protocol; the alternative is body-inspecting
  middleware, which is worse.
- `axum`'s own `DefaultBodyLimit` applies independently of the `tower-http`
  layer and defaults to 2 MB, so it has to be explicitly disabled for the
  outer ceiling to be the one that governs. A tier that raises
  `RequestBodyLimitLayer` without disabling `DefaultBodyLimit` silently keeps
  the 2 MB limit.
