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
Host: rpc.tenzro.xyz
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
| `seed` | uint | no | 42 | Sampling seed. Pins the generator so a streaming completion can be deterministically re-prefilled by a different provider if the serving one drops mid-stream — see [Streaming failover](#streaming-failover). |
| `require_signed` | bool | no | false | Verified-response mode: the response must carry a `tenzro_provenance` manifest that verifies against the provider's registered signing key, otherwise the call fails with `-32022`. Off by default — unsigned providers are fully routable. |
| `verifiable` | bool | no | false | Request a TOPLOC top-k logit commitment with the response. See [Verifiable inference](#verifiable-inference-toploc-commitments-and-challenges). Non-streaming, local single-token path only. |
| `jurisdiction` | string | no | — | Comma-separated jurisdiction pin: ISO 3166-1 alpha-2 country codes and/or bloc tokens (e.g. `"DE,EU"`), case-insensitive. The serving node must declare a matching locality claim or the request fails with `-32024`. See [Jurisdiction-pinned inference](#jurisdiction-pinned-inference-locality-claims-and-receipts). |
| `jurisdiction_receipt` | string | no | — | Set to `"required"` to fail the request unless the response carries a verifiable signed `tenzro_jurisdiction` receipt. Off by default — pinned routing works without receipt strictness. |
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
| `commitment` | object \| null | Present when `verifiable: true` was requested and the serving path supports commitments: `{"hash": "<64-hex>", "k": 16, "steps": <output token count>}`. The hash retrieves the full commitment via `tenzro_getInferenceCommitment` and anchors any later challenge. |
| `tenzro_jurisdiction` | object \| null | Signed jurisdiction receipt binding request/response hashes to the serving node's locality claim. `null` when the serving node declares no claim or, on the network path, when the provider's receipt failed verification against its registered announce key. See [Jurisdiction-pinned inference](#jurisdiction-pinned-inference-locality-claims-and-receipts). |

### Errors

| Code | Meaning |
|------|---------|
| -32001 | Authentication required (write tier). |
| -32602 | Missing or invalid params. |
| -32000 | Model not serving / runtime error. `data.load` carries load snapshot if at capacity. |
| -32022 | `require_signed` was set but no verifiable signed response is available — the serving node has no response signer, or the provider's provenance manifest failed verification. |
| -32023 | Settlement failed — channel debit or token transfer rejected. `data` carries `cost_wei` and `unpaid_key` (a persisted unpaid-settlement marker for retry). Never a silent free inference. |
| -32024 | Jurisdiction pin not satisfied — no serving node with a matching locality claim (routing found none, or the local node's claim does not match), or `jurisdiction_receipt: "required"` was set and no verifiable signed receipt is available. |

### Provenance lookup

The `tenzro_provenance` manifest attached to a chat response is also cached on the serving node keyed by its `content_hash`, so a relying party can retrieve it later without re-running inference. `tenzro_getProvenance` takes `{ "content_hash": "<32-byte hex, 0x optional>" }` and returns the same manifest, or error `-32004` when no manifest is cached for that hash. The manifest is the machine-readable synthetic-content marker for generated output (EU AI Act Art. 50(2)). Wrappers: Rust SDK `inference().get_provenance(hash)`, TS SDK `inference.getProvenance(hash)`, MCP `get_provenance` tool, A2A verification skill (`content_hash` metadata), CLI `tenzro provenance get`.

### Verifiable inference (TOPLOC commitments and challenges)

Provenance signing proves *who* served a response; a TOPLOC commitment proves *what the model actually computed*. When a request carries `verifiable: true`, the serving node records the top-`k` raw logits at every generated token and persists the resulting commitment durably. Anyone holding the same model weights can later re-execute the prompt+output as a **single prefill pass** — roughly two orders of magnitude cheaper than the original decode — and compare per-step logits against the commitment. A provider that quantized below its advertised precision, swapped in a smaller model, or fabricated output fails verification.

**Commitment contents.** `{k, prompt_tokens, steps: [{token_id, top_k: [{token_id, logit}]}]}` with `k = 16`. The canonical hash is `SHA-256` over the commitment's canonical byte encoding. The prompt is **never stored** — the verifier supplies it at verification time. Note that the output token ids are stored (they are what is being attested), so `verifiable: true` is an explicit opt-out of the completion-retention default for that response.

**Where commitments are available.** Local single-token (llama.cpp serial) path, non-streaming only — the SSE token channel carries no commitment, and external-engine backends (vLLM/SGLang) do not expose per-step logits. On the network path the request's `verifiable` flag is forwarded; the remote provider persists the commitment and its `commitment` object rides back verbatim in the proxied response, so challenges are always filed against the provider that served.

**Lifecycle RPCs.**

| Method | Params | Notes |
|--------|--------|-------|
| `tenzro_getInferenceCommitment` | `{commitment_hash}` | Full stored envelope `{commitment_hash, model_id, provider, created_at, commitment}`, or `null`. |
| `tenzro_verifyInferenceCommitment` | `{commitment_hash, prompt}` | Re-executes locally; requires the model loaded in serial mode. Returns `{pass, steps_total, steps_passed, failing_steps}` plus serving context. |
| `tenzro_fileInferenceChallenge` | `{commitment_hash, challenger, reason?}` | Open to any caller. Model and provider are read from the stored envelope, so filings cannot misattribute. Draws a stake-weighted committee seeded by the finalized-block hash. |
| `tenzro_getInferenceChallenge` | `{challenge_id}` | Full challenge record (committee, votes, tally) or `null`. |
| `tenzro_listInferenceChallenges` | `{status?, provider?}` | `{count, challenges}` sorted newest first. Status ∈ `voting_commit`, `voting_reveal`, `upheld`, `dismissed`. |
| `tenzro_commitChallengeVote` | `{challenge_id, voter, commit_hash}` | Committee seat only. `commit_hash` = `H(verdict ‖ salt ‖ challenge_id ‖ voter)`; the verdict stays hidden. When committed stake reaches `2f+1` the challenge advances to the reveal phase. |
| `tenzro_revealChallengeVote` | `{challenge_id, voter, verdict, salt}` | Discloses the sealed vote; `(verdict, salt)` must reproduce the commit. `verdict = true` upholds. `salt` is hex. |
| `tenzro_finalizeChallenge` | `{challenge_id, force?}` | Tallies revealed votes by committee stake weight. A `2f+1` stake-weighted majority to uphold upholds; otherwise dismissed. Idempotent. `force = true` closes a challenge past the reveal window with no uphold quorum. |

**Committee & quorum.** No admin token gates the verdict — the outcome is whatever the drawn, stake-weighted committee reveals. The committee is selected deterministically per dispute from the active validator set, seeded by the finalized-block hash (grinding-resistant). The quorum threshold is `2f+1` stake, computed overflow-safe as `(total_committee_stake / 3) * 2 + 1`.

**Penalties on an upheld challenge.** The provider's routing reputation is decremented through the same path as a failed call (−5), and a failure is recorded against its compute bond. The finalize response carries `reputation_penalized` and `bond_failure_recorded` booleans reporting which penalty paths actually fired. Reputation only ever increases through settled payments, so a provider cannot recover by challenging itself.

**Wrappers.** CLI `tenzro inference {get-commitment, verify-commitment, file-challenge, get-challenge, list-challenges, commit-vote, reveal-vote, finalize-challenge}`; MCP tools `get_inference_commitment`, `verify_inference_commitment`, `file_inference_challenge`, `get_inference_challenge`, `list_inference_challenges`, `commit_challenge_vote`, `reveal_challenge_vote`, `finalize_challenge`.

### Jurisdiction-pinned inference (locality claims and receipts)

Data-residency rules (GDPR transfers, sectoral regulation, sovereign-deployment policy) often require that inference run inside a specific country or regulatory bloc. Jurisdiction pinning lets a caller constrain *where* a request may be served and receive a signed record of the claim in force when it was served.

**Provider-side claim.** An operator declares the node's jurisdiction in the node config: `jurisdiction_country` (ISO 3166-1 alpha-2, e.g. `DE`, `SG`) plus optional `jurisdiction_blocs` (free-form uppercase tokens such as `EU`, `EEA`, `GDPR` — the protocol imposes no bloc vocabulary). When the node runs inside a TEE, the claim is bound to the attestation report hash at announcement time; on non-TEE nodes it is operator-asserted. The claim travels with the provider announcement, so routing peers can filter on it without a round-trip.

**Pin matching.** A pin is a comma-separated token list matched case-insensitively: a claim satisfies the pin if its country code equals any token or any of its bloc tokens equals any token. Matching is **fail-closed**: a node with no declared claim never satisfies any pin, and routing never falls back to unpinned providers — if no provider with a matching claim serves the model, the request fails with `-32024` rather than silently running elsewhere.

**Receipt.** A satisfied pinned request (and any unpinned request served by a claim-declaring node) carries a `tenzro_jurisdiction` receipt:

```json
{
  "request_hash": "0x...",
  "response_hash": "0x...",
  "model_id": "qwen3-8b",
  "provider": "0x...",
  "jurisdiction": {
    "country": "DE",
    "blocs": ["EU", "EEA"],
    "attestation_hash": "0x...",
    "declared_at": 1780000000000
  },
  "signed_at": 1780000000123,
  "signer_public_key": [/* raw bytes */],
  "signature": [/* raw bytes */],
  "algorithm": "ed25519"
}
```

`request_hash` is SHA-256 of the final user-message bytes; `response_hash` is SHA-256 of the completion text bytes. The signature covers a canonical length-prefixed preimage of every field, so a receipt pins one specific (request, response, model, provider, claim) tuple. On the network path the consuming node verifies the receipt against the provider's registered announce key and against the caller's pin before passing it through — a receipt that fails verification is stripped and the response arrives with `tenzro_jurisdiction: null` (which `jurisdiction_receipt: "required"` then converts into `-32024`).

**What a receipt is — and is not.** A receipt is a signed, attestation-bound locality *claim*: it proves which provider served the request, what claim that provider had declared, and (on TEE nodes) that the claim was bound to a hardware attestation. It is **not** cryptographic proof of geographic location — no such primitive exists. The trust anchor is the provider's stake, its attestation, and the slashing/reputation cost of a false declaration.

**Streaming.** SSE streams carry no receipts. For pinned streaming requests the fail-closed claim check runs before generation starts — refusal arrives as HTTP 412 (`jurisdiction_not_satisfied`) before the first token. That pre-stream check is the whole streaming contract; callers needing a receipt use the non-streaming path.

**Surfaces.** Simple + rich `tenzro_chat` and `tenzro_chatByIntent` (`jurisdiction` / `jurisdiction_receipt` params); OpenAI-compatible HTTP (same field names in the request body, refusals as HTTP 412 with error codes `jurisdiction_not_satisfied` / `jurisdiction_receipt_unavailable`); MCP `chat_completion` (same params); A2A inference skill (`jurisdiction` / `jurisdiction_receipt` message metadata); CLI `tenzro chat --jurisdiction "DE,EU" [--require-jurisdiction-receipt]`, `tenzro inference route --message ... --jurisdiction ...`, `tenzro inference stream --jurisdiction ...`.

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

Streams carry no jurisdiction receipts. When the request carries a `jurisdiction` pin, the fail-closed locality-claim check runs before generation starts — a node whose claim does not satisfy the pin refuses with HTTP 412 (`jurisdiction_not_satisfied`) before the first token. See [Jurisdiction-pinned inference](#jurisdiction-pinned-inference-locality-claims-and-receipts).

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

## OpenAI-compatible HTTP surface

Alongside the JSON-RPC methods, the node serves an OpenAI-compatible HTTP surface for clients and aggregators that speak the OpenAI wire format.

| Route | Method | Description |
|-------|--------|-------------|
| `/v1/models` | GET | Every model this gateway can serve: local service instances plus gossip-discovered network models. |
| `/v1/models/{id}` | GET | One model, looked up by instance ID, then model ID, then the network-models snapshot. Anything routable through chat is inspectable here. |
| `/v1/chat/completions` | POST | Chat completions, streaming and non-streaming. |
| `/api/paid/chat/completions` | POST | Same handler behind the HTTP 402 payment gate. |
| `/v1/embeddings` | POST | Text embeddings in the OpenAI wire shape. `input` is a string or an array; `dimensions` requests Matryoshka truncation where the model supports it. Served by a loaded ONNX encoder, local or a network provider. |

All listing metadata derives from registry and gossip-announcement state — providers do not maintain a separate listing configuration.

### Model listing entry

Each entry in `GET /v1/models` carries the OpenAI core fields plus the serving contract:

```json
{
  "id": "svc-8f3a…",
  "object": "model",
  "created": 1780560000,
  "owned_by": "0x4b2c…",
  "model_id": "qwen3-8b",
  "model_name": "Qwen 3 8B",
  "location": "local",
  "status": "online",
  "context_length": 32768,
  "max_output_tokens": 2048,
  "pricing": {
    "input_wei_per_token": "1000000000000",
    "output_wei_per_token": "3000000000000",
    "minimum_wei": "0",
    "pricing_model": "PerToken"
  },
  "features": {
    "streaming": true,
    "usage_in_stream": true,
    "mtp": true,
    "provenance_signing": true,
    "jurisdiction_signing": true,
    "supported_parameters": ["temperature", "top_p", "max_tokens", "stream", "draft_n", "verifiable", "jurisdiction", "jurisdiction_receipt"]
  },
  "datacenter_location": "us-central1",
  "api_endpoint": "https://…",
  "mcp_endpoint": "https://…"
}
```

- `id` — for local service instances, the instance ID; for gossip-discovered network models, the model ID. Either form is accepted as `model` in a chat request.
- `context_length` / `max_output_tokens` — from the model registry (`ModelParameters`), falling back to the built-in catalog's context length. `null` when neither source knows.
- `pricing` — wei per token as decimal strings (values exceed JSON's safe integer range). `pricing_model` is the provider's declared scheme.
- `features.mtp` — the catalog marks this model as capable of speculative decoding; opt in per request with `draft_n` (1–6).
- `features.provenance_signing` — this node signs local responses with a provenance manifest.
- `verifiable` — Tenzro extension on the chat request: non-streaming requests served by the local single-token path return a `commitment` object (TOPLOC top-k logit commitment — see [Verifiable inference](#verifiable-inference-toploc-commitments-and-challenges)). Streaming responses and external-engine backends carry no commitment.
- `features.jurisdiction_signing` — this node declares a locality claim and signs responses with a `tenzro_jurisdiction` receipt. `jurisdiction` / `jurisdiction_receipt` are accepted as Tenzro extensions on the chat request body; a pinned request the node cannot satisfy is refused with HTTP 412 (`jurisdiction_not_satisfied`), and `jurisdiction_receipt: "required"` without a verifiable receipt returns 412 (`jurisdiction_receipt_unavailable`). See [Jurisdiction-pinned inference](#jurisdiction-pinned-inference-locality-claims-and-receipts).
- `datacenter_location` — the provider's declared geography from its gossip announcement (or the node's own configured geography for local services). `null` means undeclared, not global.

The list response also carries a top-level `data_policy` object — the gateway's machine-readable data-handling declaration:

```json
{
  "object": "list",
  "data": [ … ],
  "data_policy": {
    "prompt_retention": "none",
    "completion_retention": "none",
    "stream_resume_buffer_secs": 300,
    "trains_on_data": false,
    "usage_accounting": "token_counts_cost_latency_only"
  }
}
```

Prompt and completion bodies are never written to disk. SSE chunks live in an in-memory resume buffer for `stream_resume_buffer_secs`, then expire. The usage tracker records token counts, cost, and latency only.

### Streaming usage chunks

Streaming responses always include usage — no `stream_options.include_usage` opt-in is required. The stream ends with three frames:

1. A chunk with `finish_reason` and `usage`:

```json
{"id": "chatcmpl-…", "object": "chat.completion.chunk", "created": 1780560000, "model": "qwen3-8b",
 "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
 "usage": {"prompt_tokens": 12, "completion_tokens": 48, "total_tokens": 60}}
```

2. A usage chunk with empty `choices` (the OpenAI `include_usage` final-chunk shape) carrying billing extensions:

```json
{"id": "chatcmpl-…", "object": "chat.completion.chunk", "created": 1780560000, "model": "qwen3-8b",
 "choices": [],
 "usage": {"prompt_tokens": 12, "completion_tokens": 48, "total_tokens": 60},
 "cost_wei": "156000000000000", "generation_time_ms": 2140, "tokens_per_second": 22.4}
```

`cost_wei`, `generation_time_ms`, and `tokens_per_second` are extension fields; OpenAI SDK parsers ignore them.

3. `data: [DONE]`.

Non-streaming responses carry the same `usage` object plus the same extension fields at the top level.

When the request targets a network model, the node proxies the upstream SSE byte stream unchanged — usage chunks emitted by the serving node pass through to the client. The `draft_n` parameter is forwarded with the proxied request.

### Resume

Streams support reconnection via the SSE `Last-Event-ID` header. Every event's `id` is `<completion_id>:<seq>`; a reconnecting client sends `Last-Event-ID: <completion_id>:<seq>` and the node replays buffered chunks with a higher sequence number, synthesizing `[DONE]` if the stream already finished. The buffer is in-memory and expires per `data_policy.stream_resume_buffer_secs`.

### Streaming failover

The `Last-Event-ID` resume above covers a dropped *client* connection. When the drop is on the *provider* leg — the gateway is proxying a network model and the serving provider dies mid-generation — the gateway continues the stream on a different provider without a visible restart.

The gateway captures the sampling state as it forwards tokens: the original messages, the sampling parameters (`seed`, `temperature`, `top_p`, `max_tokens`), and the assistant text emitted so far. On a mid-stream drop or stall it selects another provider serving the same model, re-sends the request with the emitted text appended as a trailing assistant prefix and `continue_final_message: true`, and streams the continuation into the same SSE. Because the seed and parameters travel with the request, the new provider re-prefills the identical prefix and resumes sampling from the same distribution.

No KV-cache bytes cross the wire — the receiving provider re-computes the prefix from the emitted text. Failover is a bounded single retry: if the continuation provider also drops, the gateway penalizes it and ends the stream. Pin `seed` in the request for byte-identical continuation; without it the runtime default seed is used and captured.

---

## Universal model compatibility

Models in the catalog are tagged by capability. The chat handler maps the on-wire content-block format to each model's native chat template using llama.cpp's template engine.

| Family | Tool calls | Thinking | Vision | Native template | Notes |
|--------|------------|----------|--------|-----------------|-------|
| Qwen3 (0.6B – 14B) | yes | yes (`<think>` tags) | no | ChatML + `<tool_call>` JSON | Tool calls expressed as `<tool_call>{...}</tool_call>` JSON; mapped to `tool_use` blocks. |
| Llama 3.1+ (8B, 70B) | yes | no | no | Llama-3 chat | Tool calls in `<|python_tag|>` envelope. |
| Mistral Nemo / Large 2 | yes | no | no | Mistral V3 tools | `[TOOL_CALLS]` prefix. |
| DeepSeek V3 | yes | yes | no | DeepSeek-V3 | Native tool calls; thinking via `<think>` like Qwen. |
| Claude (via API forward) | yes | yes | yes | passthrough | Server forwards to Anthropic-compatible endpoint without transformation. |
| GPT (via API forward) | yes | no | yes | OpenAI shim | Content blocks mapped to OpenAI `tool_calls` and back. |

A model becomes universally available when its `ModelInfo` declares its template. Catalog entries lacking a recognized template fall back to the simple shape only.

The Cortex (recurrent-depth) path uses a separate gossipsub topic (`tenzro/cortex`) and its own RPCs — `tenzro_cortexInference`, `tenzro_registerCortexWorker`. Cortex models that also expose a standard chat template can be invoked through `tenzro_chat`; pure recurrent-depth workloads stay on the Cortex RPCs.

---

## Intent routing

`tenzro_chat` requires the caller to name a `model`. Intent routing removes that requirement: the caller states an intent — a use-case, a budget, a quality floor, and where to sit on the cost↔quality axis — and the network discovers, selects, and (optionally) dispatches to a model without the caller naming one.

This is a three-tier design layered on top of the existing routing:

| Tier | Input | Output | Method |
|------|-------|--------|--------|
| **capability composition** | intent (natural-language goal + budget) | ordered plan over models, skills, tools, agents | `tenzro_orchestrate` |
| **model selection** | intent (use-case + budget + quality floor + optimize knob) | `model_id` | `tenzro_routeIntent` |
| **provider selection** | `model_id` | operator `Address` serving that model | existing `tenzro_chat` dispatch |

Model selection picks the model; the existing dispatch path then selects the provider serving it. Capability composition sits one layer above — it plans and runs a set of capabilities (which may include several model calls) to satisfy a goal. Naming a model directly (`tenzro_chat`) skips both higher tiers — nothing about the existing contract changes.

### `tenzro_routeIntent` — discovery only

Resolves an intent to a `model_id` and a fallback chain. Does **not** run inference — a read-tier method, useful for previewing the selection, caching a decision, or driving a client-side dispatch.

```json
{
  "jsonrpc": "2.0",
  "method": "tenzro_routeIntent",
  "params": {
    "use_case": "code",
    "budget": "500000000000000",
    "optimize": 0.3,
    "quality_floor": "cheap",
    "est_input_tokens": 400,
    "est_output_tokens": 256,
    "payer_did": "did:tenzro:machine:0x...",
    "payer_address": "0x..."
  },
  "id": 1
}
```

| Field | Type | Required | Default | Notes |
|-------|------|----------|---------|-------|
| `use_case` | string | yes | — | One of `chat`, `code`, `reasoning`, `research`, `summarize`, `extract`, `embed`. Case-insensitive. `research` biases toward the strong tier for open-ended synthesis. |
| `budget` | string (u128) | no | none | Per-request cost cap in wei (10^-18 TNZO). Candidate models whose estimated cost exceeds this are pre-filtered out at discovery time. Sent as a string because a u128 exceeds the JSON safe-integer range. |
| `optimize` | float | no | 0.5 | Continuous cost↔quality knob in `[0.0, 1.0]`. `0.0` = cheapest acceptable model, `1.0` = strongest acceptable model. |
| `quality_floor` | string | no | `cheap` | Minimum tier the selection may return: `cheap` or `strong`. A floor of `strong` refuses to route to a cheap-tier model even when the budget would allow it. |
| `est_input_tokens` | uint | no | 0 | Estimated prompt tokens, used to compute the per-request cost estimate against `budget`. |
| `est_output_tokens` | uint | no | 0 | Estimated completion tokens, used the same way. |
| `payer_did` | string | no | — | DID whose rolling-window spend cap is checked at admission. Independent of the per-request `budget`: `budget` bounds this single call, `payer_did` bounds the DID's aggregate spend over its policy window. |
| `payer_address` | string | no | — | Payer wallet address (hex). Enables the wallet-balance hard ceiling: the estimated cost of the selected model is checked against the payer's on-chain balance, and an unaffordable request is rejected at discovery time — before any provider is dialed or any spend recorded. |

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "model_id": "qwen3-8b",
    "tier": "cheap",
    "estimated_cost": "336000000000000",
    "fallback_chain": ["qwen3-14b", "deepseek-v3"],
    "reason": "use_case=code optimize=0.30 within budget; cheap tier meets quality_floor"
  }
}
```

| Field | Type | Notes |
|-------|------|-------|
| `model_id` | string | The selected model. |
| `tier` | string | `cheap` or `strong` — the quality tier of the selected model. |
| `estimated_cost` | string (u128) | Estimated cost of the call in wei, given `est_input_tokens`/`est_output_tokens` at the selected model's price. String for the same range reason as `budget`. |
| `fallback_chain` | array of string | Ordered alternate `model_id`s to try if the primary is unavailable at dispatch, best-first. |
| `reason` | string | Human-readable explanation of the selection. |

Errors:

| Code | Meaning |
|------|---------|
| -32602 | Unknown `use_case`, malformed `budget`, or `optimize` outside `[0.0, 1.0]`. |
| -32000 | No catalog model satisfies the intent (budget too low, `quality_floor` unmet, over the `payer_did` window cap, over the `payer_address` wallet balance, or empty catalog). |

### `tenzro_chatByIntent` — discover and dispatch

Resolves the intent exactly as `tenzro_routeIntent` does, then dispatches the prompt to the selected model through the standard chat path in one call. A write-tier method — it consumes tokens and bills the caller, subject to the same auth, settlement, and `-32023` rules as `tenzro_chat`.

```json
{
  "jsonrpc": "2.0",
  "method": "tenzro_chatByIntent",
  "params": {
    "use_case": "code",
    "budget": "500000000000000",
    "optimize": 0.3,
    "message": "Write a Rust function that reverses a linked list.",
    "max_tokens": 512,
    "caller_address": "0x..."
  },
  "id": 1
}
```

It accepts every `tenzro_routeIntent` field plus the `tenzro_chat` simple-shape dispatch fields (`message`, `max_tokens`, `temperature`, `top_p`, `repeat_penalty`, `require_signed`, `caller_address`, `channel_id`, `channel_update_sig`). The response is the `tenzro_chat` response object with the resolved `model_id`, augmented with the `tier`, `estimated_cost`, and `fallback_chain` from the routing decision so the caller can see what the network picked.

### Cross-surface wrappers

The same operations are exposed on every surface:

| Surface | Discovery | Discover + dispatch | Capability composition |
|---------|-----------|---------------------|------------------------|
| JSON-RPC | `tenzro_routeIntent` | `tenzro_chatByIntent` | `tenzro_orchestrate` |
| MCP | `route_by_intent` tool | `chat_completion` tool with `use_case` (and no `model`) | `orchestrate` tool |
| A2A | `inference` skill, intent-routing prompt | `inference` skill, intent chat prompt | `inference` skill, orchestration prompt |
| CLI | `tenzro inference route --use-case ...` | `tenzro inference route --use-case ... --message ...`, or `tenzro chat --use-case ...` | `tenzro inference orchestrate --intent ...` |
| Rust SDK | `inference().route_intent(&params)` | `inference().chat_by_intent(&params, messages)` | `inference().orchestrate(&request)` |
| TS SDK | `inference.routeIntent(params)` | `inference.chatByIntent(params)` | `inference.orchestrate(params)` |

The MCP `chat_completion` tool and the CLI `tenzro chat` command both make `model` optional: when `model` is omitted and a `use_case` is supplied, they resolve the model via the router before dispatching, so intent routing is available without a distinct entry point. Supplying `model` explicitly skips routing.

---

## Capability composition

`tenzro_orchestrate` is one layer above `tenzro_chatByIntent`. Where `chatByIntent` resolves a single model and runs one completion, `orchestrate` takes a natural-language goal and plans an ordered set of capabilities — models, registered skills, registered tools, and agent/swarm delegation — then runs them, reusing the same single inference, skill, tool, and settlement paths as everything else. Provenance, usage accounting, and settlement are identical to a direct call for each model step.

### Planning

A planner turns the intent, the live capability catalog (models + `CF_SKILLS` + `CF_TOOLS` + swarm/agent registry), the payer's wallet balance, and per-model usage/reputation into a plan: an ordered list of steps, each naming a capability kind. Two planners exist:

- **deterministic planner** — an always-available guardrail. Reads the catalog and produces a default plan; never itself calls a model.
- **LLM planner** — routes its own plan-generation call through the model router (a `reasoning` intent), then falls back to the deterministic planner on any failure. This keeps orchestration available even when no model can be reached.

Plans are bounded (max 8 steps; re-planning iterations clamped to `[1, 6]`, default 1).

### Wallet ceiling

When `payer_address` is set, the plan's **aggregate** estimated cost across all model steps is summed and checked against the payer's on-chain wallet balance before any step runs. An over-budget plan is rejected up front with `-32004` — the network never starts running a plan it cannot pay for. This is the plan-level analogue of the per-call wallet ceiling on `tenzro_routeIntent`.

### Request

```json
{
  "jsonrpc": "2.0",
  "method": "tenzro_orchestrate",
  "params": {
    "intent": "Research recent decentralized-training results and draft a one-paragraph summary.",
    "use_case": "research",
    "budget": "500000000000000000",
    "payer_did": "did:tenzro:machine:0x...",
    "payer_address": "0x...",
    "max_iterations": 2
  },
  "id": 1
}
```

| Field | Type | Required | Default | Notes |
|-------|------|----------|---------|-------|
| `intent` | string | yes | — | The natural-language goal. Empty string returns `-32602`. |
| `use_case` | string | no | `chat` | Primary use-case hint for model steps. Same vocabulary as `tenzro_routeIntent`. |
| `budget` | string (u128) | no | none | Per-request cost cap in wei applied to model steps. Sent as a string (u128 range). |
| `payer_did` | string | no | — | DID whose rolling-window spend cap is checked on model steps. |
| `payer_address` | string | no | — | Payer wallet address (hex). Enables the plan-level wallet ceiling described above. |
| `max_iterations` | uint | no | 1 | Max re-plan iterations, clamped to `[1, 6]`. `1` = single-shot. |

### Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "plan": {
      "steps": [ /* planned capability steps */ ],
      "rationale": "research goal → strong model synthesis after a web-search skill",
      "planner": "llm"
    },
    "steps": [
      {"kind": "skill", "output": "…retrieved sources…", "detail": {"skill": "web-search"}},
      {"kind": "model", "output": "…drafted summary…", "detail": {"model_id": "qwen3-14b"}}
    ],
    "estimated_cost": "412000000000000000",
    "iterations": 1
  }
}
```

| Field | Type | Notes |
|-------|------|-------|
| `plan` | object | The plan that ran: `{steps, rationale, planner}`. `planner` is `deterministic` or `llm`. |
| `steps` | array | One result per executed step, in order. Each is `{kind, output, detail}` where `kind` ∈ `model`, `skill`, `tool`, `agent`, `swarm`. |
| `estimated_cost` | string (u128) | Aggregate estimated cost across model steps, wei, decimal string. |
| `iterations` | uint | Number of plan/execute iterations that ran. |

### Errors

| Code | Meaning |
|------|---------|
| -32602 | Empty `intent`, malformed `budget`/`use_case`, or an invalid plan. |
| -32004 | Over budget — the plan's aggregate estimated cost exceeds the `payer_address` wallet balance. `data` carries `estimated` and `balance` (both decimal strings). Also returned when the plan requires a capability the network cannot supply. |
| -32603 | A required capability runtime was unavailable. |
| -32000 | Other orchestration error. |

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
- **Provider attestation in chat responses.** The verification API (`api.tenzro.xyz/verify/inference`) already attests inference results. Inlining attestations into every chat response is a separate workstream (would require TEE-served models and on-the-fly attestation generation).
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
