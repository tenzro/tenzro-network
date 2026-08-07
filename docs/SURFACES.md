# Client Surfaces

Every capability a Tenzro node has is reachable from every client surface. This
document says what those surfaces are, how that guarantee is maintained, and
what it does _not_ mean.

## The seven surfaces

| Surface        | Transport   | Discovery                    | Call by name              |
| -------------- | ----------- | ---------------------------- | ------------------------- |
| JSON-RPC       | `:8545`     | `tenzro_listRpcMethods`      | the method itself         |
| REST           | `:8545`     | `GET /v1/rpc`                | `POST /v1/rpc/{method}`   |
| MCP            | `:3001/mcp` | `list_rpc_methods` tool      | `call_rpc` tool           |
| A2A            | `:3002`     | `rpc-gateway` skill          | `rpc-gateway` skill       |
| Rust SDK       | —           | `client.gateway().methods()` | `client.gateway().call()` |
| TypeScript SDK | —           | `client.gateway.methods()`   | `client.gateway.call()`   |
| CLI            | —           | `tenzro rpc methods`         | `tenzro rpc call`         |
| OpenClaw       | —           | `list_rpc_methods()`         | `call_rpc()`              |

## How the guarantee holds

Coverage was measured before this existed and came back between 35% and 76%
depending on the surface — and the surfaces disagreed about _which_ methods they
covered. The AI control plane was reachable only from the CLI; hosting from
everything except the TypeScript SDK. That is not a gap you close once: every
new RPC re-opens it in five places, silently, and the developer who needs the
method finds out at the point of use.

So coverage is a property of the architecture rather than of anyone's diligence.
There is exactly one list of methods — `ADMIN_METHODS` + `OPEN_METHODS` in
`crates/tenzro-node/src/rpc_gates.rs` — and the classification test refuses to
pass while any dispatch arm is missing from it. That list is therefore not a
copy of the method surface; it _is_ the method surface. Every surface's
discovery reads it at runtime, so none ships a hand-maintained list that can
drift, and a client talking to a node newer than itself simply sees more.

`crates/tenzro-node/tests/surface_parity_integration.rs` pins the claim: it
asserts the directory reports every served method, that each surface ships both
discovery and a by-name call, and — separately, because a router that was never
merged answers 404 for everything — that the REST gateway is actually mounted.

## Named bindings still matter

The gateway is the floor, not the ceiling. Common paths keep dedicated bindings
with real signatures, documentation, and types: `/v1/chat/completions`,
`/v1/files`, `/v1/databases`, `tenzro files`, `client.wallet()`, the 500-odd
curated MCP tools. Those exist because a developer expects a particular
vendor-compatible shape at a particular path, and because a typed signature
catches at compile time what a `Value` catches at runtime.

What the gateway removes is the _cliff_ — the point where a caller's SDK simply
cannot express something the node can do.

### Why not a binding per method per surface

It was considered and is the wrong answer, and not only on effort:

- For **MCP** it would actively make the server worse. Tool-selection accuracy
  falls as the list grows, and the server already carries 536 tools. Five
  hundred more near-identical entries would cost every agent accuracy on the
  tools it actually wanted.
- For the **SDKs** it produces thousands of functions whose parameters are all
  `Value` / `unknown`, because there is no per-method schema to type them from.
  That is autocomplete, not type safety.
- In every case the wrappers drift from the dispatcher the moment someone adds a
  method and forgets one language — which is the failure being fixed.

## The gateway widens ergonomics, not authorization

A call through any gateway runs through the same dispatcher entry point as a
direct JSON-RPC request, behind:

1. the operator **admin-token** gate,
2. the **API-key scope** gate, and
3. the **default-deny classification** — a method nobody classified is refused
   before dispatch.

A method a caller could not reach on `:8545` is a method they cannot reach
through any gateway. The parity tests assert this directly: an admin method
without the operator token is 401, a `storage`-scoped method without a
correctly-scoped key is 401, and an unclassified method is 404.

One thing does change, and it is worth stating rather than discovering. An
operator exposing MCP but not JSON-RPC has been relying on the MCP tool list as
a de-facto allowlist. After this, MCP reaches what the gates allow rather than
what someone remembered to write a tool for. That is intended — a tool list is
not an authorization model, and treating it as one meant the real gate was never
the one being reasoned about — but an operator wanting a narrower surface should
use API-key scopes, which are the mechanism designed for it.

## Discovery output

`tenzro_listRpcMethods` takes optional `namespace` and `contains` filters; the
unfiltered directory is ~925 rows. Each entry carries the gate class and the
API-key scope, so a caller can tell "I need a differently-scoped key" from "I
need the operator's token" without provoking the error first:

```
$ tenzro rpc methods --contains database
  Matched              12 of 925 served

  [open ] tenzro_createDatabase          scope:database
  [open ] tenzro_databaseQuery           scope:database
  [open ] tenzro_listDatabaseEngines
  …
```

`tenzro_listDatabaseEngines` carries no scope deliberately: it reports which
engines a node can serve — node capability advertisement, the same class of fact
as `/v1/models` — and gating it would mean a caller cannot discover what a node
offers without first being issued a key by its operator, which defeats
network-level resource discovery.

## Body ceilings are per-tier, and the JSON-RPC root is not the JSON tier

A request body limit cannot be raised by an inner layer underneath a smaller
outer one, so the ceilings are applied per sub-router rather than globally.
There are three tiers:

| Tier  | Ceiling | Routes                                                                                                                                                            |
| ----- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| JSON  | 2 MB    | `/health`, `/v1/models`, `/v1/generation`, the files and database routes, the gateway, and the generation routes whose bodies are a prompt or a numeric series    |
| Media | 64 MB   | `/v1/embeddings`, `/v1/images/edits`, `/v1/videos`, the Tenzro-namespaced detection / segmentation / video-embedding routes — **and the JSON-RPC root, `POST /`** |
| Audio | 128 MB  | `/v1/audio/transcriptions`, `/v1/audio/speech`                                                                                                                    |

The third row of the media tier is the one worth reading twice. `POST /` is the
JSON-RPC endpoint, and its name says JSON, but several methods dispatched there
carry base64 media by design:

- `tenzro_mediaGen_publishOutput` — how a media-generation worker returns a
  finished render
- `tenzro_mediaGen_fetchInput` / `fetchLatent` / `fetchOutput` — the same bytes
  travelling the other way

Under the 2 MB JSON ceiling a worker would render an image successfully, spend
the GPU time, and then fail to publish it with a `413`. The job surfaced as
failed with no indication that the _transport_ refused it rather than the
render; a 121-frame clip is an order of magnitude worse. The JSON-RPC root is
therefore mounted in its own tier at the media ceiling.

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
