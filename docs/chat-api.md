# Tenzro Chat API

Specification for `tenzro_chat` and `tenzro_chatStream` — the two RPC methods that drive AI inference on the Tenzro Network.

This document defines both methods at the JSON-RPC layer. The same call shapes are exposed through MCP (`chat_completion` tool) and the A2A `inference` skill.

## Status

Pre-alpha. Not version-locked. Names, fields, and event types may change without deprecation cycles until the network has live external users.

## Two call shapes

`tenzro_chat` accepts two distinct request shapes. Both are **first-class** — neither is deprecated, neither is a "compatibility" mode. Callers pick the shape that fits their use case.

| Shape | Use case | Distinguishing field |
|-------|----------|----------------------|
| **simple** | Scripts, bots, faucets, REPL chat, monitoring, single-shot generation | `message: <string>` |
| **rich** | Multi-turn agents, tool-calling, RAG, structured assistant responses | `messages: [...]` |

Routing rule:

```
if "messages" in params:    rich
elif "message" in params:   simple
else:                       error -32602
```

No silent upgrades. No heuristics. The caller's choice of field determines the shape.

---

## Authentication

The RPC server runs in one of three auth modes, selected by the `TENZRO_MCP_AUTH` environment variable on the node:

| Mode | Behavior |
|------|----------|
| `tiered` (default) | Read methods (`tenzro_listModels`, `tenzro_getBlock`, etc.) are public. Write methods (`tenzro_chat`, `tenzro_signAndSendTransaction`, `tenzro_serveModel`, etc.) require a DPoP-bound bearer JWT. |
| `full` | All methods require a DPoP-bound bearer JWT. |
| `false` | Auth disabled. Suitable only for local development. |

`tenzro_chat` and `tenzro_chatStream` are write methods (they consume tokens and bill the caller). Under `tiered` and `full`, both require an authenticated request.

### Obtaining a token

Mint a DPoP-bound bearer JWT directly via one of three onboarding RPCs:

| RPC | Identity type |
|-----|---------------|
| `tenzro_onboardHuman` | Human user, KYC tier 0+ |
| `tenzro_onboardDelegatedAgent` | Machine controlled by a human DID (act-chain entry) |
| `tenzro_onboardAutonomousAgent` | Machine acting on its own behalf |

The JWT is issued per OAuth 2.1 with Rich Authorization Requests (RFC 9396) for fine-grained scopes (allowed methods, max amounts, time bounds). The JWT carries a `cnf.jkt` claim — the RFC 7638 thumbprint of the DPoP key — so every request must be accompanied by a fresh DPoP proof signed by that key.

For browser-based flows, the node exposes OAuth 2.1 discovery at `GET /.well-known/oauth-authorization-server` (RFC 8414) and protected-resource metadata at `GET /.well-known/oauth-protected-resource` (RFC 9728).

### Sending the token

```http
POST / HTTP/1.1
Host: rpc.tenzro.network
Content-Type: application/json
Authorization: DPoP <bearer-jwt>
DPoP: <jws-compact-dpop-proof>

{"jsonrpc":"2.0","method":"tenzro_chat","params":{...},"id":1}
```

The DPoP proof (RFC 9449) is a per-request JWS with claims `htm` (HTTP method), `htu` (request URL), `iat`, and `jti`. SDK clients pick up `TENZRO_BEARER_JWT` and `TENZRO_DPOP_PROOF` from the environment automatically.

Unauthenticated calls to write methods return JSON-RPC error `-32001` with `data.www_authenticate` carrying the OAuth challenge per RFC 9728. Tokens can be revoked individually via `tenzro_revokeJwt` (by `jti`) or cascadingly via `tenzro_revokeDid` (revokes all JWTs in the DID's act-chain).

---

## Simple shape

For one-shot generation. The handler internally constructs a single-turn `[{role: "user", content: <message>}]` and dispatches to the model.

### Request

```json
{
  "jsonrpc": "2.0",
  "method": "tenzro_chat",
  "params": {
    "model": "qwen3-8b",
    "message": "What is the capital of France?",
    "max_tokens": 256,
    "temperature": 0.7,
    "top_p": 0.9,
    "repeat_penalty": 1.1,
    "require_signed": false,
    "caller_address": "0x..."
  },
  "id": 1
}
```

| Field | Type | Required | Default | Notes |
|-------|------|----------|---------|-------|
| `model` (or `model_id`) | string | yes | — | Model identifier from `tenzro_listModels`. Either key accepted. |
| `message` | string | yes | — | The prompt. Presence of this field selects the simple shape. |
| `max_tokens` | uint | no | 512 | Maximum output tokens. |
| `temperature` | float | no | 0.7 | Sampling temperature. |
| `top_p` | float | no | 0.9 | Nucleus sampling. |
| `repeat_penalty` | float | no | 1.1 | Repetition penalty. |
| `draft_n` | uint | no | — | Multi-Token-Prediction draft count (1–6). Requires a drafter paired with the target model. |
| `require_signed` | bool | no | false | Verified-response mode: the response must carry a `tenzro_provenance` manifest that verifies against the provider's registered signing key, otherwise the call fails with `-32022`. Off by default — unsigned providers are fully routable. |
| `caller_address` | string | no | — | TNZO address billed for the inference. If absent, no on-chain billing. |
| `channel_id` | string | no | — | Open micropayment channel to debit instead of a direct transfer. Requires `channel_update_sig`. |
| `channel_update_sig` | string | no | — | Hex Ed25519 signature by the payer over the next cumulative channel state, authorizing the debit. |

### Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "output": "The capital of France is Paris.",
    "model_id": "qwen3-8b",
    "input_tokens": 8,
    "output_tokens": 7,
    "generation_time_ms": 142,
    "tokens_per_second": 49.3,
    "cost_wei": "210000000000000",
    "settlement": { "status": "settled", "via": "transfer" },
    "location": "local",
    "load": {
      "active_requests": 1,
      "max_concurrent": 8,
      "utilization_percent": 12.5,
      "load_level": "low"
    },
    "tenzro_provenance": {
      "content_hash": "0x...",
      "model_id": "qwen3-8b",
      "provider": "0x...",
      "signed_at": 1780000000000,
      "assertion": "ai-generated",
      "signer_public_key": [/* raw bytes */],
      "signature": [/* raw bytes */],
      "algorithm": "ed25519"
    }
  }
}
```

| Field | Type | Notes |
|-------|------|-------|
| `output` | string | The generated completion text. |
| `model_id` | string | Resolved model identifier. |
| `input_tokens` | uint | Prompt tokens. |
| `output_tokens` | uint | Generated tokens. |
| `generation_time_ms` | uint | Wall-clock generation duration. Local path only. |
| `tokens_per_second` | float | Throughput. Local path only. |
| `cost_wei` | string | Total cost in wei (10^-18 TNZO). Local path only. |
| `settlement` | object | `{"status": "settled", "via": "channel"\|"transfer"}` when payment cleared, `{"status": "not_applicable"}` when no billing applied (zero cost, no `caller_address`, or no billing wallet on the serving node). Local path only. |
| `location` | string | `"local"` if served by this node, `"network"` if forwarded to a peer. |
| `provider` | string | Serving provider identifier. Network path only. |
| `load` | object | Provider load snapshot. Useful for client-side routing decisions. Local path only. |
| `tenzro_provenance` | object \| null | Signed provenance manifest over the output bytes. `null` when the serving node has no response signer (unsigned serving is fully supported) or, on the network path, when the provider's manifest failed verification against its registered announce key. Signature preimage: `content_hash \|\| model_id \|\| provider \|\| signed_at_ms (le_u64) \|\| assertion`. |

### Errors

| Code | Meaning |
|------|---------|
| -32001 | Authentication required (write tier). |
| -32602 | Missing or invalid params. |
| -32000 | Model not serving / runtime error. `data.load` carries load snapshot if at capacity. |
| -32022 | `require_signed` was set but no verifiable signed response is available — the serving node has no response signer, or the provider's provenance manifest failed verification. |
| -32023 | Settlement failed — channel debit or token transfer rejected. `data` carries `cost_wei` and `unpaid_key` (a persisted unpaid-settlement marker for retry). Never a silent free inference. |

### Provenance lookup

The `tenzro_provenance` manifest attached to a chat response is also cached on the serving node keyed by its `content_hash`, so a relying party can retrieve it later without re-running inference. `tenzro_getProvenance` takes `{ "content_hash": "<32-byte hex, 0x optional>" }` and returns the same manifest, or error `-32004` when no manifest is cached for that hash. The manifest is the machine-readable synthetic-content marker for generated output (EU AI Act Art. 50(2)). Wrappers: Rust SDK `inference().get_provenance(hash)`, TS SDK `inference.getProvenance(hash)`, MCP `get_provenance` tool, A2A verification skill (`content_hash` metadata), CLI `tenzro provenance get`.

---

## Rich shape

For multi-turn conversations, system prompts, tool calls, vision input, and structured responses. Built around content blocks.

### Request

```json
{
  "jsonrpc": "2.0",
  "method": "tenzro_chat",
  "params": {
    "model": "qwen3-8b",
    "system": "You are a TNZO trading agent. Use tools when prices are needed.",
    "messages": [
      {"role": "user", "content": "What is TNZO trading at?"},
      {"role": "assistant", "content": [
        {"type": "thinking", "thinking": "I should query the price oracle."},
        {"type": "tool_use", "id": "tu_01", "name": "chainlink_get_price", "input": {"pair": "TNZO/USD"}}
      ]},
      {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "tu_01", "content": "0.42"}
      ]}
    ],
    "tools": [
      {
        "name": "chainlink_get_price",
        "description": "Read a Chainlink price feed.",
        "input_schema": {
          "type": "object",
          "properties": {
            "pair": {"type": "string", "description": "Asset pair, e.g. TNZO/USD"}
          },
          "required": ["pair"]
        }
      }
    ],
    "max_tokens": 1024,
    "temperature": 0.7,
    "top_p": 0.9,
    "stop_sequences": ["</answer>"],
    "reasoning_effort": "medium",
    "caller_address": "0x..."
  },
  "id": 1
}
```

| Field | Type | Required | Default | Notes |
|-------|------|----------|---------|-------|
| `model` (or `model_id`) | string | yes | — | Model identifier. |
| `messages` | array | yes | — | Conversation history. Presence selects rich shape. |
| `system` | string \| Block[] | no | — | System prompt. Accepts a string or an array of `text` blocks (so `cache_control` can be applied to system text). |
| `tools` | object[] | no | [] | Tool schemas. See **Tools** section. |
| `max_tokens` | uint | no | 1024 | |
| `temperature` | float | no | 0.7 | |
| `top_p` | float | no | 0.9 | |
| `stop_sequences` | string[] | no | [] | Up to 4 stop sequences. |
| `reasoning_effort` | string | no | `"medium"` | `"low"` \| `"medium"` \| `"high"`. Bounds the `thinking` block budget on models that support extended thinking. Ignored otherwise. |
| `caller_address` | string | no | — | Billing address. |

### Messages

A message is `{role: "user" | "assistant", content: <string> | <Block[]>}`.

If `content` is a string, the SDK normalizes it to `[{type: "text", text: <string>}]`. The on-wire format is always blocks for assistant messages and may be either for user messages.

The `system` field is **not** a message — it is a top-level parameter applied to the model template separately, consistent with Anthropic's Messages API.

### Content blocks

| Type | Direction | Schema |
|------|-----------|--------|
| `text` | both | `{type: "text", text: string, cache_control?: CacheControl}` |
| `thinking` | assistant only | `{type: "thinking", thinking: string}` |
| `tool_use` | assistant only | `{type: "tool_use", id: string, name: string, input: object}` |
| `tool_result` | user only | `{type: "tool_result", tool_use_id: string, content: string \| Block[], is_error?: bool}` |
| `image` | user only | `{type: "image", source: {type: "base64", media_type: string, data: string}}` |

`CacheControl`: `{type: "ephemeral"}` — marks the block as a cache breakpoint. Subsequent identical-prefix calls reuse the KV cache, billing only the new tokens. Ephemeral cache entries live ≤5 min.

`image` blocks are reserved in the schema even though no model in the current catalog accepts them. A model that does accept images will declare `modality: "vision"` in its `ModelInfo`; routing to a non-vision model with an image block returns error `-32602`.

### Tools

```json
{
  "name": "string",
  "description": "string",
  "input_schema": <JSON Schema object>
}
```

`input_schema` is a JSON Schema (draft 2020-12) describing the tool's input. The model is instructed to emit `tool_use` blocks whose `input` validates against this schema. Schema validation is performed server-side before the response is returned; invalid `input` causes the assistant turn to be regenerated up to one retry, then surfaced as an error.

Tool names must match `^[a-zA-Z0-9_-]{1,64}$`.

### Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "id": "msg_01H8ZQ...",
    "model": "qwen3-8b",
    "role": "assistant",
    "content": [
      {"type": "thinking", "thinking": "Price came back as 0.42 USD."},
      {"type": "text", "text": "TNZO is trading at $0.42."}
    ],
    "stop_reason": "end_turn",
    "stop_sequence": null,
    "usage": {
      "input_tokens": 142,
      "output_tokens": 28,
      "cache_creation_input_tokens": 0,
      "cache_read_input_tokens": 0
    },
    "cost": 0.00064,
    "location": "local"
  }
}
```

| `stop_reason` | Meaning |
|---------------|---------|
| `end_turn` | Model finished naturally. |
| `max_tokens` | Hit `max_tokens` limit. |
| `stop_sequence` | Hit a sequence in `stop_sequences`. `stop_sequence` field is set. |
| `tool_use` | Model emitted one or more `tool_use` blocks. The client is expected to execute them and return `tool_result` blocks in the next turn. |

### Tool execution loop

1. Client sends `messages` + `tools`.
2. Server returns response with `stop_reason: "tool_use"` and `content` containing one or more `tool_use` blocks.
3. Client executes tools, builds a new `user` message with `tool_result` blocks (one per `tool_use`, matching `tool_use_id`).
4. Client appends the assistant's previous response and the new user message to `messages` and calls again.
5. Loop until `stop_reason: "end_turn"` (or `max_tokens`).

Tools are executed by the **client**, not the server. The Tenzro node never invokes external tools on the model's behalf. This keeps the trust boundary at the caller and avoids the server holding tool credentials.

---

## Streaming

`tenzro_chatStream` returns a Server-Sent Events stream. The event grammar depends on the request shape.

### Initiating

```http
POST /chat-stream HTTP/1.1
Accept: text/event-stream
Content-Type: application/json
Authorization: DPoP <bearer-jwt>
DPoP: <jws-compact-dpop-proof>

{"jsonrpc":"2.0","method":"tenzro_chatStream","params":{...},"id":1}
```

Or via JSON-RPC `tenzro_chatStream` returning a `subscription_id`, with the SSE pulled from `GET /events/{subscription_id}`.

### Simple shape events

```
event: delta
data: {"text": "The capital "}

event: delta
data: {"text": "of France "}

event: delta
data: {"text": "is Paris."}

event: done
data: {"input_tokens": 8, "output_tokens": 7, "cost": 0.00021, "stop_reason": "end_turn"}
```

Two event types: `delta` (zero or more) and `done` (exactly one).

### Rich shape events

Modeled on Anthropic's Messages streaming format.

```
event: message_start
data: {"id": "msg_01...", "model": "qwen3-8b", "role": "assistant", "content": [], "usage": {"input_tokens": 142, "output_tokens": 0}}

event: content_block_start
data: {"index": 0, "content_block": {"type": "thinking", "thinking": ""}}

event: content_block_delta
data: {"index": 0, "delta": {"type": "thinking_delta", "thinking": "Let me check..."}}

event: content_block_stop
data: {"index": 0}

event: content_block_start
data: {"index": 1, "content_block": {"type": "tool_use", "id": "tu_01", "name": "chainlink_get_price", "input": {}}}

event: content_block_delta
data: {"index": 1, "delta": {"type": "input_json_delta", "partial_json": "{\"pair"}}

event: content_block_delta
data: {"index": 1, "delta": {"type": "input_json_delta", "partial_json": "\":\"TNZO/USD\"}"}}

event: content_block_stop
data: {"index": 1}

event: message_delta
data: {"delta": {"stop_reason": "tool_use", "stop_sequence": null}, "usage": {"output_tokens": 28}}

event: message_stop
data: {}

event: ping
data: {}
```

| Event | When emitted |
|-------|--------------|
| `message_start` | Once, at the start. Carries metadata; `content` is empty. |
| `content_block_start` | Once per block. Carries the block envelope (without final content). |
| `content_block_delta` | Zero or more times per block. Delta types: `text_delta`, `thinking_delta`, `input_json_delta` (for `tool_use.input`). |
| `content_block_stop` | Once per block. |
| `message_delta` | Once at end. Carries `stop_reason`, final `usage`. |
| `message_stop` | Once at end. Terminator. |
| `ping` | Keep-alive. Emitted every 15s if no other events have been sent. Clients should ignore. |

`thinking` blocks are emitted only by models with extended-thinking support. When `reasoning_effort: "low"` is set, the server may suppress thinking blocks entirely even on capable models.

#### Streaming granularity (current limitation)

The first cut of `/chat-stream` (rich shape) emits **one `*_delta` per content block**, not per token. The model generates synchronously to completion and the resulting blocks are framed into the SSE event grammar (`message_start` → per-block `start` / single `delta` / `stop` → `message_delta` → `message_stop`). Clients see correct ordering and final usage counts, but they do not see partial text accumulating token by token.

True per-token streaming for the rich shape lands when `ModelRuntime::generate_chat_with_tools_stream` is implemented — that path will interleave `text_delta` events with mid-stream tool-call extraction. The simple shape (`tenzro_chatStream` with `message:`) already streams per token via `generate_chat_stream`.

This limitation does not apply to:
- Simple-shape SSE (per-token deltas via the existing OpenAI-compatible `/v1/chat/completions` path)
- The non-streaming rich path (`tenzro_chat` with `messages:`), which always returned the full message in one response.

---

## Universal model compatibility

Models in the catalog are tagged by capability. The chat handler maps the on-wire content-block format to each model's native chat template using llama.cpp's template engine.

| Family | Tool calls | Thinking | Vision | Native template | Notes |
|--------|------------|----------|--------|-----------------|-------|
| Qwen3 (0.6B – 14B) | yes | yes (`<think>` tags) | no | ChatML + Hermes tools | Tool calls expressed as `<tool_call>{...}</tool_call>` JSON; mapped to `tool_use` blocks. |
| Llama 3.1+ (8B, 70B) | yes | no | no | Llama-3 chat | Tool calls in `<|python_tag|>` envelope. |
| Mistral Nemo / Large 2 | yes | no | no | Mistral V3 tools | `[TOOL_CALLS]` prefix. |
| DeepSeek V3 | yes | yes | no | DeepSeek-V3 | Native tool calls; thinking via `<think>` like Qwen. |
| Claude (via API forward) | yes | yes | yes | passthrough | Server forwards to Anthropic-compatible endpoint without transformation. |
| GPT (via API forward) | yes | no | yes | OpenAI shim | Content blocks mapped to OpenAI `tool_calls` and back. |

A model becomes universally available when its `ModelInfo` declares its template. Catalog entries lacking a recognized template fall back to the simple shape only.

The Cortex (recurrent-depth) path uses a separate gossipsub topic (`tenzro/cortex`) and its own RPCs — `tenzro_cortexInference`, `tenzro_registerCortexWorker`. Cortex models that also expose a standard chat template can be invoked through `tenzro_chat`; pure recurrent-depth workloads stay on the Cortex RPCs.

---

## Implementation notes

These are notes for the implementer; not part of the public contract.

### Routing in `handle_chat`

```rust
async fn handle_chat(node, params) -> Result<Value, JsonRpcError> {
    let params = unwrap_params(params)?;
    if params.get("messages").is_some() {
        handle_chat_rich(node, params).await
    } else if params.get("message").is_some() {
        handle_chat_simple(node, params).await
    } else {
        Err(JsonRpcError::missing("message or messages"))
    }
}
```

`handle_chat_simple` is the existing `handle_chat` body, unchanged — renamed only.

### Rich path additions

- `crates/tenzro-types/src/model.rs` — add `ContentBlock` enum, `ChatMessage` (already exists with `role: String, content: String` — needs widening), `ToolSchema`, `ToolUse`, `ToolResult`.
- `crates/tenzro-model/src/runtime.rs` — `generate_chat` already exists. Add `generate_chat_with_tools` that accepts `tools: &[ToolSchema]`, threads them through llama.cpp's chat template (which accepts a `tools` array per recent versions), and parses tool calls from the raw output using per-template extractors.
- `crates/tenzro-node/src/rpc.rs` — `handle_chat_rich` (non-streaming) and `handle_chat_stream_rich` (SSE) live here directly. SSE events are emitted via `async_stream::stream!` over `axum::response::sse::{Sse, Event}` with `KeepAlive::default()` providing the 15s `ping`. Tool-schema validation rejects invalid names (regex `^[a-zA-Z0-9_-]{1,64}$`) and non-object `input_schema` at request parse time.
- Routes mounted in `RpcServer::serve` (rpc.rs ~line 122): `POST /chat-stream` is wired alongside `POST /v1/chat/completions` under both the gated and ungated branches. The gated branch goes through `tenzro_payments::middleware::payment_gate_handler` for HTTP 402 enforcement.

### Network forwarding

When a node receives `tenzro_chat` for a model it does not serve, it forwards to a peer per the existing logic in `handle_chat`. The forwarded payload **must** preserve the request shape — a rich-shape forward goes out as rich, not down-converted to simple. Down-conversion would silently drop tools, system prompts, and content blocks.

The forward travels over the `tenzro/infer` ALPN on the node's iroh endpoint. The serving peer is addressed by its iroh `EndpointId` (resolved via Pkarr — never by IP), which is published as the `iroh_endpoint_id` field on the model's endpoint record. Inspect it with `tenzro_listModelEndpoints` (or the MCP `list_model_endpoints` tool): a non-empty `iroh_endpoint_id` identifies the serving node; an empty string means the service is local-only. A response returned this way carries `location: "network"` and the serving `provider`.

### Billing

Cost calculation is identical for both shapes: `input_tokens × input_price + output_tokens × output_price`. Tool-use response tokens (the `tool_use` blocks themselves) count as output tokens. Cached input tokens are billed at a discounted rate (TBD; design says 10% of normal rate, matching Anthropic's prompt caching).

Settlement runs on the serving node before the response is returned. With a `caller_address` and non-zero cost, the node either debits an open micropayment channel (when `channel_id` + `channel_update_sig` are supplied) or executes a direct on-chain transfer. A rejected debit or transfer fails the request with `-32023` and persists an unpaid-settlement marker keyed in `data.unpaid_key` — settlement failure is never a silent free inference. The outcome is reported in the response `settlement` field.

Differential pricing for rich vs. simple is not implemented in this spec. If the network adopts it later, it would surface as a per-model `pricing.rich_multiplier` field in `ModelInfo`.

---

## Out of scope

- **Logprobs.** No consumer is asking for them; can be added without a breaking change.
- **Provider attestation in chat responses.** The verification API (`api.tenzro.network/verify/inference`) already attests inference results. Inlining attestations into every chat response is a separate workstream (would require TEE-served models and on-the-fly attestation generation).
- **Function-calling other than `tools`.** OpenAI's older `functions` API is not supported. Callers using `functions` must migrate to `tools`.
- **Embeddings.** A separate RPC (`tenzro_embed`) covers them.

---

## Test plan

- **Simple shape parity**: existing `tenzro_chat` callers (CLI `tenzro chat`, faucet, monitoring) keep working byte-for-byte. Existing test in `crates/tenzro-cli/tests/` should pass without modification.
- **Rich shape end-to-end**: spawn a test that sends a `messages` array including a `system` block, receives a `tool_use`, returns a `tool_result`, receives a final `text` answer. Asserts `stop_reason` transitions correctly.
- **Streaming**: SSE smoke test for both shapes — assert event counts and ordering.
- **Tool schema validation**: invalid `input_schema` (e.g., not a JSON Schema object) returns `-32602` at request time, not at response time.
- **Cross-shape isolation**: sending both `message` and `messages` is an error, not a silent precedence.
- **Network forwarding**: rich-shape request to a non-serving node forwards to a serving peer with the rich payload intact.
