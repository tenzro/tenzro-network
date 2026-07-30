# Tenzro Chat API

Specification for `tenzro_chat` and `tenzro_chatStream` — the two RPC methods that drive AI inference on the Tenzro Network.

This document defines both methods at the JSON-RPC layer. The same call shapes are exposed through MCP (`chat_completion` tool) and the A2A `inference` skill.

## Status

Pre-alpha. Not version-locked. Names, fields, and event types may change without deprecation cycles until the network has live external users.

## Two call shapes

`tenzro_chat` accepts two distinct request shapes. Both are fully supported — neither is deprecated, neither is a "compatibility" mode. Callers pick the shape that fits their use case.

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
| `top_k` | uint | no | — | Top-k truncation. Omitted leaves the candidate set untruncated by rank. |
| `min_p` | float | no | — | Minimum-probability floor relative to the most likely token. Omitted disables the stage. |
| `repeat_penalty` | float | no | 1.1 | Repetition penalty over the recent window. |
| `frequency_penalty` | float | no | 0.0 | Per-occurrence logit penalty. |
| `presence_penalty` | float | no | 0.0 | Flat logit penalty for any token already present. |
| `stop` | string or array | no | — | Stop sequences. Generation halts when the decoded text ends with one of them, and the matched suffix is trimmed from the returned text. |
| `draft_n` | uint | no | — | Multi-Token-Prediction draft count (1–6). Requires a drafter paired with the target model. |
| `seed` | uint | no | 42 | Sampling seed. Pins the generator so a streaming completion can be deterministically re-prefilled by a different provider if the serving one drops mid-stream — see [Streaming failover](#streaming-failover). |
| `require_signed` | bool | no | false | Verified-response mode: the response must carry a `tenzro_provenance` manifest that verifies against the provider's registered signing key, otherwise the call fails with `-32022`. Off by default — unsigned providers are fully routable. |
| `verifiable` | bool | no | false | Request a TOPLOC top-k logit commitment with the response. See [Verifiable inference](#verifiable-inference-toploc-commitments-and-challenges). Non-streaming, local single-token path only. |
| `jurisdiction` | string | no | — | Comma-separated jurisdiction pin: ISO 3166-1 alpha-2 country codes and/or bloc tokens (e.g. `"DE,EU"`), case-insensitive. The serving node must declare a matching locality claim or the request fails with `-32024`. See [Jurisdiction-pinned inference](#jurisdiction-pinned-inference-locality-claims-and-receipts). |
| `jurisdiction_receipt` | string | no | — | Set to `"required"` to fail the request unless the response carries a verifiable signed `tenzro_jurisdiction` receipt. Off by default — pinned routing works without receipt strictness. |
| `caller_address` | string | no | — | TNZO address billed for the inference. If absent, no on-chain billing. |
| `channel_id` | string | no | — | Open micropayment channel to debit instead of a direct transfer. Requires `channel_update_sig`. |
| `channel_update_sig` | string | no | — | Hex Ed25519 signature by the payer over the next cumulative channel state, authorizing the debit. |
| `provider` | string | no | — | Pins the call to one provider's wallet address. Set by intent routing, which scored a specific announcement at its advertised price. A pin naming another operator outranks any locally-resolved service. If the pinned offer is no longer announced the call fails with `-32004` rather than serving a different provider at a price the consumer never priced against. |
| `app_id` | string | no | — | Registered app whose developer margin is added on top of the network cost and routed to that app's wallet. An unknown or deactivated `app_id` fails with `-32602` instead of silently dropping the margin. |

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
    "settlement": {
      "status": "settled",
      "via": "transfer",
      "commission_wei": "10500000000000",
      "provider_wei": "199500000000000",
      "margin_wei": "0",
      "provider": "0x...",
      "app_id": null
    },
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
| `settlement` | object | `{"status": "settled", "via": "channel"\|"transfer", "commission_wei", "provider_wei", "margin_wei", "provider", "app_id"}` when payment cleared, `{"status": "not_applicable"}` when no billing applied (zero cost, no `caller_address`, or no billing wallet on the settling node). `commission_wei` and `provider_wei` sum to the network cost — commission is carved out of the quoted price, not added to it, so the consumer pays exactly the advertised offer. `margin_wei` is the developer margin added on top of the network cost and routed to `app_id`'s wallet; both are `0`/`null` without an `app_id`. `provider` is the wallet actually paid. The `channel` path reports `commission_wei: 0` because channel commission and developer margin are carved once at channel finalize rather than per update. Present on both paths: when this node forwards to a peer it settles that peer's leg itself. |
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
| -32004 | The pinned `provider` no longer announces the requested model. The call fails rather than silently serving a different provider at a price the consumer never priced against — route again to pick a live offer. |
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
| `top_k` | uint | no | — | Top-k truncation. Omitted leaves the candidate set untruncated by rank. |
| `min_p` | float | no | — | Minimum-probability floor relative to the most likely token. |
| `frequency_penalty` | float | no | 0.0 | Per-occurrence logit penalty. |
| `presence_penalty` | float | no | 0.0 | Flat logit penalty for any token already present. |
| `stop_sequences` | string \| string[] | no | [] | Stop sequences. The matched suffix is trimmed from the returned text. |
| `reasoning_effort` | string | no | `"medium"` | `"low"` \| `"medium"` \| `"high"`. Bounds the `thinking` block budget on models that support extended thinking. Ignored otherwise. |
| `caller_address` | string | no | — | Billing address. |
| `provider` | string | no | — | Pins the call to one provider's wallet address, same contract as the simple shape. |
| `app_id` | string | no | — | Registered app whose developer margin is added on top of the network cost, same contract as the simple shape. |

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

### Images

`image` blocks carry raw PNG, JPEG, WebP, or GIF bytes, base64-encoded. `media_type` is the label; the serving projector reads the actual format from the bytes.

An image reaches a model through its multimodal projector — a companion GGUF (Gemma 4's SigLIP tower, Kimi K3's MoonViT-3d) that the model's catalog entry declares and `tenzro model download` fetches alongside the weights. The projector is loaded at model-load time, and a model serving with one takes attachments; a model without one serves text.

Read `accepts_media` on `tenzro_listModelEndpoints` or `tenzro_getModelEndpoint` to see which locally-served models take images. It is reported for locally-served models only — a model reached over the network is served by another node, which answers for its own capability.

Sending an image to a model that serves text only returns `-32000` with a message naming the model. A projector that has no tower for the attached modality (an audio clip to a vision-only projector) is refused the same way. Undecodable base64 in an `image` block returns `-32602`.

Attachments bind to the prompt in traversal order: the nth image in the request is the nth attachment the model sees. Order runs message by message, and within a message block by block, including images nested in a `tool_result`. Images in the `system` parameter are not collected — `system` is rendered as text.

Images and tools compose. A turn may carry both, and the model can answer with `tool_use` blocks about what it saw.

A model serving images runs one request at a time rather than under continuous batching, for the same reason a model with a draft model does: the multimodal decode path holds the context for the whole turn.

**Surfaces.** Rich-shape `tenzro_chat` and `tenzro_chatStream` carry `image` blocks as above. The OpenAI-compatible path uses an [`image_url` content part](#message-content-parts) with the bytes inlined as a `data:` URI. The MCP `chat_completion` tool takes a flat `images` array of base64 strings alongside its text, bound in array order. `tenzro chat` attaches a local file with `/image <path>` at the REPL, sniffing the media type from the bytes. The simple `tenzro_chat` shape carries a bare `message` string with no field an attachment could ride on, so it serves text whatever the model's projector.

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

Rich-shape streaming on `POST /chat-stream` serves local weights only, which bounds two request shapes:

| Condition | Response |
|-----------|----------|
| The model resolves to a network peer rather than local weights | HTTP 501 `stream_forward_unsupported`. Use the non-streaming `tenzro_chat` rich shape, which forwards to the peer. |
| A `provider` pin names an address other than this node's payee | HTTP 409 `provider_pin_unsupported`. Serving it here would bill this node's payee for an offer the consumer scored against someone else. Drop the pin to stream locally, or use the non-streaming rich shape to reach the pinned provider. |

Simple-shape streaming forwards to peers normally; neither restriction applies to it.

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

True per-token streaming for the rich shape requires `ModelRuntime::generate_chat_with_tools_stream`, which is not implemented yet — that path will interleave `text_delta` events with mid-stream tool-call extraction. The simple shape (`tenzro_chatStream` with `message:`) already streams per token via `generate_chat_stream`.

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
| `/v1/responses` | POST | The Responses shape over the same handler — see [Responses endpoint](#responses-endpoint). |
| `/api/paid/chat/completions` | POST | Same handler behind the HTTP 402 payment gate. |
| `/v1/embeddings` | POST | Text embeddings in the OpenAI wire shape. `input` is a string or an array; `dimensions` requests Matryoshka truncation where the model supports it. Served by a loaded ONNX encoder, local or a network provider. |
| `/v1/audio/transcriptions` | POST | Speech recognition over the ASR runtimes — see [Audio transcriptions](#audio-transcriptions). `multipart/form-data`. |
| `/v1/images/generations` | POST | Text-to-image over the media-generation job queue — see [Image generations](#image-generations). |
| `/v1/images/edits` | POST | Image-to-image over the same queue — see [Image edits](#image-edits). `multipart/form-data`. |
| `/v1/videos` | POST | Video rendering over the same queue — see [Video renders](#video-renders). `multipart/form-data`, and a job resource rather than a synchronous render. |
| `/v1/videos/{id}` | GET | One video job's status. |
| `/v1/videos/{id}/content` | GET | A finished clip's bytes. |
| `/v1/tenzro/forecasts` | POST | Timeseries forecasting — see [Forecasts](#forecasts). |
| `/v1/tenzro/detections` | POST | Object detection — see [Detections](#detections). |
| `/v1/tenzro/segmentations` | POST | Promptable segmentation — see [Segmentations](#segmentations). |
| `/v1/tenzro/video/embeddings` | POST | Clip embedding — see [Video embeddings](#video-embeddings). |
| `/v1/generation` | GET | Recorded token counts, latency, provider and cost for one completion id — see [Generation stats lookup](#generation-stats-lookup). |

All listing metadata derives from registry and gossip-announcement state — providers do not maintain a separate listing configuration.

### Modality matrix

Every modality the node serves has a slot on this surface, and which slot it takes follows one rule: where the vendor publishes a path for the modality, it is served at that path in that shape; where none exists, it is served under `/v1/tenzro/…`.

| Modality | Endpoint | Body | Runtime |
|----------|----------|------|---------|
| Text generation | `POST /v1/chat/completions`, `POST /v1/responses` | JSON | `ModelRuntime` |
| Text embedding | `POST /v1/embeddings` | JSON | `TextEmbeddingRuntime` |
| Speech recognition | `POST /v1/audio/transcriptions` | multipart | `AudioRuntime` |
| Text to image | `POST /v1/images/generations` | JSON | media-generation queue |
| Image to image | `POST /v1/images/edits` | multipart | media-generation queue |
| Text or image to video | `POST /v1/videos` | multipart | media-generation queue |
| Timeseries forecast | `POST /v1/tenzro/forecasts` | JSON | `TimeseriesRuntime` |
| Object detection | `POST /v1/tenzro/detections` | JSON | `DetectionRuntime` |
| Segmentation | `POST /v1/tenzro/segmentations` | JSON | `SegmentationRuntime`, `TextSegmentationRuntime` |
| Clip embedding | `POST /v1/tenzro/video/embeddings` | JSON | `VideoRuntime` |

The namespace split is forward-compatibility, not a quality distinction. A bare `/v1/detections` would collide with the vendor's own path the day they publish one, and every caller written against ours would break on the upgrade; `/v1/tenzro/detections` cannot collide, so both can coexist and a modality added later has an obvious slot rather than needing a bespoke client.

Body shape follows the path being mirrored. The four `/v1/tenzro/…` routes carry media as base64 inside JSON under the 64 MiB media body ceiling rather than the 2 MiB JSON ceiling, because they mirror no vendor multipart shape and a caller reaching four routes benefits from one body convention across them.

Image embedding has no route of its own by design. An image reaches a vision encoder as an `image_url` content part on a chat message, and the similarity read is `tenzro_imageTextSimilarity` over JSON-RPC — a similarity score between two artifacts is neither a completion, an embedding list, nor a rendered file, so no path on this surface is the right home for it.

### Request parameters

The standard OpenAI sampling fields are honoured on the local serving path and forwarded verbatim on the network path.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `model` | string | — | Instance ID or model ID from `/v1/models`. |
| `messages` | array | — | Chat turns. Each `content` is a string or an array of typed parts — see [Message content parts](#message-content-parts). |
| `temperature` | float | 0.7 | Range 0.0–2.0. |
| `top_p` | float | 0.9 | Nucleus sampling. |
| `top_k` | uint | — | Omitted leaves the candidate set untruncated by rank. |
| `min_p` | float | — | Probability floor relative to the most likely token. Omitted disables the stage. |
| `frequency_penalty` | float | 0.0 | Per-occurrence logit penalty. |
| `presence_penalty` | float | 0.0 | Flat logit penalty for any token already present. |
| `repetition_penalty` | float | 1.1 | Penalty over the recent window. |
| `stop` | string or array | — | Stop sequences. The matched suffix is trimmed from the returned text, so `native_finish_reason: "stop_sequence"` is the only signal that one fired. |
| `seed` | uint | 42 | Pins the generator. Required for byte-identical [streaming failover](#streaming-failover). |
| `max_tokens` | uint | 512 | Output budget. Reaching it sets `finish_reason: "length"`. |
| `stream` | bool | false | SSE streaming. |
| `stream_options` | object | — | `{"include_usage": true}` appends the OpenAI usage-only chunk. |
| `user` | string | — | Opaque end-user tag. Not persisted by the gateway — forwarded to the serving provider so an operator's own abuse accounting sees the value the caller sent. |

Omitting `top_k` or `min_p` leaves that truncation stage out entirely rather than inserting a neutral-valued one.

Tenzro extensions ride on the same request body; OpenAI SDKs pass unknown fields through unchanged.

| Field | Type | Notes |
|-------|------|-------|
| `models` | array | Fallback model IDs tried in order when `model` has no reachable offer. See [Model fallback and provider pinning](#model-fallback-and-provider-pinning). |
| `provider` | object | `{"only": [...], "ignore": [...]}` — restrict which providers may serve the request. |
| `draft_n` | uint | 1–6. Opt in to Multi-Token-Prediction speculative decoding. The target model must be catalog-marked MTP-capable (`features.mtp`). |
| `verifiable` | bool | Request a TOPLOC top-k logit commitment. Non-streaming, local single-token path only. |
| `jurisdiction` | string | Comma-separated locality pin, e.g. `"DE,EU"`. Hard-filters to providers with a matching claim. |
| `jurisdiction_receipt` | string | `"required"` fails the request unless a signed locality receipt comes back. |

`n` is rejected unless it is `1` — the network bills per completion, and fanning one request into several would hide the multiplier. `logprobs`, `top_logprobs`, and `logit_bias` are not accepted; `verifiable` is the logit-commitment path.

### Message content parts

A message `content` is either a bare string or an array of typed parts. Both shapes are accepted, and a proxied request reaches the serving provider in the shape the client sent, so a provider that accepts only one form still receives a valid request.

| Part `type` | Payload | Fields |
|-------------|---------|--------|
| `text` | `text` | The text of this part. |
| `image_url` | `image_url` | `url` — a `data:` URI carrying base64 bytes for a locally-served model, or an `https://` URL for a peer that fetches. `detail` — resolution hint (`auto` / `low` / `high`). |
| `input_audio` | `input_audio` | `data` — base64 audio bytes. `format` — `wav` or `mp3`. |
| `file` | `file` | `file_id` for a pre-uploaded file, or `file_data` + `filename` to inline base64 bytes. |

```json
{
  "model": "qwen3-8b",
  "messages": [
    {
      "role": "user",
      "content": [
        { "type": "text", "text": "What is in this image?" },
        { "type": "image_url", "image_url": { "url": "data:image/png;base64,iVBORw0KGgo...", "detail": "high" } }
      ]
    }
  ]
}
```

An `image_url` part renders on a locally-served model that loaded a multimodal projector — read `accepts_media` on `tenzro_listModelEndpoints` to see which do. The bytes must be inlined as a `data:` URI: a serving node does not fetch a caller-named remote resource, so an `https://` URL is refused with `400 invalid_image_part` and the message says to inline instead. Undecodable base64 is refused the same way.

`input_audio` and `file` parts, and any `image_url` sent to a model serving text only, are refused with `400 unsupported_content_part` naming the part type, rather than served a completion that ignored the part. On the network path the parts array is forwarded intact, including remote URLs, so a peer serving a model that renders them can answer.

Attachments bind to the prompt in part order: the nth image across the whole request is the nth attachment the model sees. A request carrying one generates in full before the response opens, so `stream: true` delivers the reply as a single delta followed by the usual finish and usage chunks.

Multiple `text` parts are newline-joined when flattened for a text-only runtime. Jurisdiction receipts hash the parts array as its JSON, so image URLs and inlined bytes are bound by the receipt alongside the text. [Streaming failover](#streaming-failover) carries the parts through to the continuation provider — a continuation that dropped them would re-prefill a different context.

### Model fallback and provider pinning

`models` lists fallback model IDs in preference order. The gateway tries `model` first, then each `models` entry, and serves the first one an admitted provider offers. Blank entries and duplicates of an earlier candidate are dropped. When nothing in the list resolves, the 404 names every candidate that was tried.

```json
{
  "model": "qwen3-8b",
  "models": ["qwen3-4b", "gemma4-e4b"],
  "provider": { "ignore": ["0x9c1d…"] },
  "messages": [{ "role": "user", "content": "Hello" }]
}
```

The response's `model` field is the candidate actually served, so a caller always knows which one answered.

`provider` narrows which providers may serve the request:

| Field | Type | Notes |
|-------|------|-------|
| `only` | array | Non-empty restricts routing to these providers. |
| `ignore` | array | Removes providers from consideration. Applied after `only`. |

An entry matches a provider's announced name or its address in either the base58 or hex spelling, case-insensitively, with an optional `0x` prefix. A pin that admits no provider for any candidate model yields `404 model_not_found` — the gateway does not silently serve an excluded provider.

The pin also governs [streaming failover](#streaming-failover): a continuation provider must satisfy it. The fallback `models` list does not, because a continuation replays the already-emitted text as an assistant turn and a different model tokenizes that prefix differently. A stream stays on the model it started with.

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
    "pricing_model": "PerToken",
    "prompt": "0.00000005",
    "completion": "0.00000015",
    "request": "0",
    "currency": "USD",
    "tnzo_usd": "0.05"
  },
  "features": {
    "streaming": true,
    "usage_in_stream": true,
    "mtp": true,
    "provenance_signing": true,
    "jurisdiction_signing": true,
    "supported_parameters": ["temperature", "top_p", "top_k", "min_p", "max_tokens", "frequency_penalty", "presence_penalty", "repetition_penalty", "stop", "seed", "stream", "stream_options", "user", "draft_n", "verifiable", "jurisdiction", "jurisdiction_receipt", "models", "provider"]
  },
  "datacenter_location": "us-central1",
  "datacenters": [{ "country_code": "US" }],
  "api_endpoint": "https://…",
  "mcp_endpoint": "https://…"
}
```

- `id` — for local service instances, the instance ID; for gossip-discovered network models, the model ID. Either form is accepted as `model` in a chat request.
- `context_length` / `max_output_tokens` — from the model registry (`ModelParameters`), falling back to the built-in catalog's context length. `null` when neither source knows.
- `pricing` — `input_wei_per_token` / `output_wei_per_token` / `minimum_wei` are TNZO wei as decimal strings (values exceed JSON's safe integer range) and are the amounts that settle under the default `PerToken` scheme. `pricing_model` is the provider's declared scheme, and it decides what a settled call is charged on: `PerToken` meters every consumed dimension at its own rate; `PerRequest` is a flat charge per call regardless of what it consumed; `PerComputeTime` charges the measured latency by the millisecond; `Dynamic` meters as `PerToken` then scales the result toward the average that model's finished calls have settled at on the serving node, bounded to between half and twice the metered figure so one outlier in a thin market cannot multiply a bill without limit. `minimum_wei` is the floor under all four. A node settling a call it did not serve holds the provider's signed pricing configuration but not the provider's settlement history, so a `Dynamic` quote settles at its metered cost when the settling node has no anchor rather than guessing a scale.
- `pricing.prompt` / `pricing.completion` / `pricing.request` — the same prices in USD per token, as decimal strings, for marketplaces that list in fiat. Derived from the operator's declared TNZO listing rate, echoed as `pricing.tnzo_usd`; `currency` is always `USD`. An operator who declares no rate omits all five keys rather than publishing a price they never quoted — a listing with no `prompt` key is unpriced in USD, not free. The rate is a commercial declaration by the gateway (`listing_tnzo_usd_micro` in the node config, in millionths of a dollar), not an oracle reading.
- `features.mtp` — the catalog marks this model as capable of speculative decoding; opt in per request with `draft_n` (1–6).
- `features.provenance_signing` — this node signs local responses with a provenance manifest.
- `verifiable` — Tenzro extension on the chat request: non-streaming requests served by the local single-token path return a `commitment` object (TOPLOC top-k logit commitment — see [Verifiable inference](#verifiable-inference-toploc-commitments-and-challenges)). Streaming responses and external-engine backends carry no commitment.
- `features.jurisdiction_signing` — this node declares a locality claim and signs responses with a `tenzro_jurisdiction` receipt. `jurisdiction` / `jurisdiction_receipt` are accepted as Tenzro extensions on the chat request body; a pinned request the node cannot satisfy is refused with HTTP 412 (`jurisdiction_not_satisfied`), and `jurisdiction_receipt: "required"` without a verifiable receipt returns 412 (`jurisdiction_receipt_unavailable`). See [Jurisdiction-pinned inference](#jurisdiction-pinned-inference-locality-claims-and-receipts).
- `datacenter_location` — the provider's declared geography from its gossip announcement (or the node's own configured geography for local services). `null` means undeclared, not global.
- `datacenters` — one entry per declared serving locality, keyed by ISO 3166-1 alpha-2 `country_code`, taken from the operator's jurisdiction claim (its own for local services, the claim on the signed announcement for network providers). On TEE hardware the claim is bound to an attestation report hash. The country code is never derived from `datacenter_location`: `eu-west` and `ap-southeast` span many countries, and projecting them would misdeclare where the hardware sits. `null` means the operator declared no jurisdiction — distinct from an empty array, which would assert it serves from nowhere.

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
    "usage_accounting": "metered_units_cost_latency_only"
  }
}
```

Prompt and completion bodies are never written to disk. SSE chunks live in an in-memory resume buffer for `stream_resume_buffer_secs`, then expire. The usage tracker records the metered units, cost, and latency only — never the content that produced them.

### Streaming usage chunks

Every stream ends with a `finish_reason` chunk that also carries `usage` and the billing extensions, so a caller learns what it was billed without opting into anything:

```json
{"id": "chatcmpl-…", "object": "chat.completion.chunk", "created": 1780560000, "model": "qwen3-8b",
 "choices": [{"index": 0, "delta": {}, "finish_reason": "stop", "native_finish_reason": "stop_sequence"}],
 "usage": {"prompt_tokens": 12, "completion_tokens": 48, "total_tokens": 60},
 "cost_wei": "156000000000000", "generation_time_ms": 2140, "tokens_per_second": 22.4}
```

Two finish reasons ride together. `finish_reason` is the OpenAI vocabulary — `stop`, `length`, `tool_calls`, or `content_filter` — so SDK parsers that branch on it keep working. `native_finish_reason` beside it is the exact cause reported by whatever produced the tokens, which is strictly more information than the normalized form carries.

On a locally served model that is the inference engine's own cause:

| `native_finish_reason` | `finish_reason` | Meaning |
|---|---|---|
| `eos` | `stop` | The model emitted an end-of-sequence token. |
| `stop_sequence` | `stop` | One of the `stop` strings matched. The matched suffix is trimmed out of the returned text, so this is the only signal that it fired. |
| `length` | `length` | The `max_tokens` budget was exhausted. |

On a network model the serving peer's own spelling passes through verbatim, so a caller reading `native_finish_reason` sees what that engine reported rather than a lossy translation of it.

`cost_wei`, `generation_time_ms`, and `tokens_per_second` are extension fields; OpenAI SDK parsers ignore them.

Setting `stream_options: {"include_usage": true}` appends the OpenAI empty-`choices` usage chunk after it, repeating the same numbers in the shape OpenAI SDKs look for:

```json
{"id": "chatcmpl-…", "object": "chat.completion.chunk", "created": 1780560000, "model": "qwen3-8b",
 "choices": [],
 "usage": {"prompt_tokens": 12, "completion_tokens": 48, "total_tokens": 60},
 "cost_wei": "156000000000000", "generation_time_ms": 2140, "tokens_per_second": 22.4}
```

`data: [DONE]` terminates the stream in both cases.

Non-streaming responses carry the same `usage` object plus the same extension fields at the top level, and their single choice carries both `finish_reason` and `native_finish_reason`.

When the request targets a network model, the node forwards the upstream SSE stream as it arrives — usage chunks emitted by the serving node pass through to the client. The only rewrite is on frames that carry a `finish_reason`: the serving peer's spelling moves to `native_finish_reason` and `finish_reason` is normalized onto the OpenAI vocabulary, so a client sees one vocabulary regardless of which engine answered. The `draft_n` parameter is forwarded with the proxied request.

### Generation stats lookup

The counts and cost of a generation ride on the response that carried it. A streamed caller frequently never reads them: the terminal chunk arrives after the text the caller was waiting for, and closing the connection there is ordinary client behaviour. `GET /v1/generation?id=<completion_id>` resolves the completion id the caller already holds back to what was recorded when the generation finished.

```
GET /v1/generation?id=chatcmpl-9f3c8a1e-…
```

```json
{
  "id": "chatcmpl-9f3c8a1e-…",
  "model": "qwen3-8b",
  "provider": "0x8f2b…",
  "input_tokens": 12,
  "output_tokens": 48,
  "total_tokens": 60,
  "bytes_in": 214,
  "bytes_out": 1108,
  "cost_wei": "156000000000000",
  "latency_ms": 2140,
  "tokens_per_second": 22.4,
  "created": 1780560000
}
```

The id is the `chatcmpl-…` returned by any of the chat routes, or the `request_id` of an inference dispatched through JSON-RPC. `provider` is the payee address of the node that served the tokens — the local payee for a locally served generation, the serving peer for a routed one. `bytes_in` / `bytes_out` are the byte counts of what that path moved: prompt and completion text for a local generation, HTTP request and response bodies for a routed one, so they are not directly comparable between the two. `tokens_per_second` is omitted when the recorded latency is zero.

`input_tokens` is the whole prompt as an OpenAI-compatible caller counts it, so a cache read is inside it rather than beside it. `total_tokens` is every token dimension summed — prompt, completion, both cache directions, and image-derived — so it exceeds `input_tokens + output_tokens` whenever a call wrote to cache or carried an image.

The fields above are the ones every generation has. A model is billed on more than tokens, and the dimensions that carry that work appear **only when the call consumed them**, so a plain chat completion is not padded with zeroed media fields:

| Field | Unit | Present when |
|-------|------|--------------|
| `cached_read_tokens` | tokens | The prompt hit a cache. Already counted inside `input_tokens`; reported separately because it is priced separately. |
| `cached_write_tokens` | tokens | The prompt was written to cache for later reuse. |
| `reasoning_loops` | loops | A recurrent-depth model billed on loop depth rather than tokens. |
| `image_tokens` | tokens | An image was in the prompt, tokenized per that model family's descriptor rather than by one shared formula. |
| `audio_seconds` | whole seconds | Audio was transcribed or generated. Rounded up from the recorded milliseconds. |
| `video_seconds` | whole seconds | Video was embedded or generated. Rounded up on the same basis. |
| `frames` | frames | A video generation produced frames. |
| `pixel_steps` | pixel-steps | A diffusion pipeline ran: `width × height × steps × frames`. |

`cost_wei` and `pixel_steps` are decimal strings; every other field is a JSON number. Both exceed what a JSON number carries exactly — `pixel_steps` on a long video generation runs past 2⁵³, where `JSON.parse` would silently round it.

A generation is recorded when it finishes, so 404 means the id is unknown to this node, the generation is still running, or it failed before completing. The route is not payment-gated — reading back counts the caller was already told is not itself billable.

The same read is available over JSON-RPC as `tenzro_getGeneration`:

```json
{"jsonrpc": "2.0", "id": 1, "method": "tenzro_getGeneration",
 "params": {"id": "chatcmpl-9f3c8a1e-…"}}
```

It returns the same object, and answers `-32004` where the HTTP route answers 404.

### Usage history

`tenzro_getGeneration` resolves one id. `tenzro_listInferenceUsage` reads the history behind it, and what it returns depends on which of the two optional filters you supply:

| `model_id` | `provider` | Returns |
|-----------|-----------|---------|
| set | set | `records` — the matching individual records |
| set | — | `model_stats` — that model's rollup |
| — | set | `provider_stats` — that provider's rollup |
| — | — | `global`, plus `models` and `providers` breakdowns |

```json
{"jsonrpc": "2.0", "id": 1, "method": "tenzro_listInferenceUsage",
 "params": {"model_id": "qwen3-8b"}}
```

This is the stored shape rather than the reshaped one, and it differs from `tenzro_getGeneration` in three ways: every dimension is present whether or not the call consumed it, durations stay in milliseconds (`audio_ms` / `video_ms`, not whole seconds), and `provider_id` is the address as an array of 32 bytes rather than a hex string. A rollup carries its dimensions under `total_units`, and names its money field for its side of the trade — `total_cost` on a model or global rollup, `total_revenue` on a provider's.

Usage survives restart: records and rollups are persisted and read back on boot.

### Responses endpoint

`POST /v1/responses` serves the Responses shape by rewriting the request into a chat body, handing it to the same handler that serves `/v1/chat/completions`, and rewriting the result back. Offer resolution, provider pinning, [streaming failover](#streaming-failover), settlement, provenance signing and the jurisdiction receipt therefore behave identically on both routes — this endpoint adds a vocabulary, not a second execution path.

| Field | Type | Maps to | Notes |
|-------|------|---------|-------|
| `model` | string | `model` | Instance ID or model ID from `/v1/models`. |
| `input` | string or array | `messages` | A bare string becomes one user turn. An array is a list of message items — see below. |
| `instructions` | string | leading `system` message | Blank or whitespace-only is dropped rather than sent as an empty turn. |
| `max_output_tokens` | uint | `max_tokens` | |
| `temperature` | float | `temperature` | |
| `top_p` | float | `top_p` | |
| `stream` | bool | `stream` | Streams the typed event sequence below. |
| `metadata` | object | — | Echoed on the response object. Not forwarded to the provider. |
| `store` | bool | — | Accepted and always reported back as `false`. |

Every field the Responses schema does not name reaches the chat body untouched, so the standard sampling fields (`top_k`, `min_p`, `stop`, the penalties, `stream_options`, `user`) and the [Tenzro extensions](#request-parameters) (`models`, `provider`, `seed`, `jurisdiction`, `jurisdiction_receipt`, `draft_n`, `verifiable`) work here exactly as they do on `/v1/chat/completions`.

Each `input` item is a message: an optional `type` that must be `message`, an optional `role` defaulting to `user`, and `content` as a string or an array of parts. The two surfaces name the same parts differently:

| Responses part | Chat part | Fields |
|----------------|-----------|--------|
| `input_text` (also `output_text`, `text`) | `text` | `text`. |
| `input_image` | `image_url` | `image_url` as a bare `https://` or `data:` URL string, plus a sibling `detail`. An object-valued `image_url` is also read. A `file_id` image reference is refused. |
| `input_file` | `file` | `file_id`, or `file_data` + `filename`. Flattened at the part level here, nested under `file` in the chat shape. |
| `input_audio` | `input_audio` | `data` (base64) and `format`. Same shape on both. |

The response object carries the Responses fields plus the same Tenzro extensions the chat body carries:

```json
{
  "id": "resp_9f3c…",
  "object": "response",
  "created_at": 1780560000,
  "status": "completed",
  "model": "qwen3-8b",
  "output": [{
    "id": "msg_9f3c…",
    "type": "message",
    "status": "completed",
    "role": "assistant",
    "content": [{ "type": "output_text", "text": "Hello.", "annotations": [] }]
  }],
  "output_text": "Hello.",
  "instructions": null,
  "max_output_tokens": null,
  "temperature": 0.7,
  "top_p": 0.9,
  "metadata": {},
  "store": false,
  "incomplete_details": null,
  "error": null,
  "usage": { "input_tokens": 12, "output_tokens": 48, "total_tokens": 60 },
  "native_finish_reason": "eos",
  "cost_wei": "156000000000000",
  "generation_time_ms": 2140,
  "tokens_per_second": 22.4
}
```

`usage` uses the Responses names — `input_tokens` and `output_tokens` where the chat shape says `prompt_tokens` and `completion_tokens`. `native_finish_reason` carries the same engine-reported cause described under [streaming usage chunks](#streaming-usage-chunks). `cost_wei`, `generation_time_ms`, `tokens_per_second`, `tenzro_provenance`, `tenzro_jurisdiction` and `commitment` are the identical bytes the chat surface returns, so a caller that verifies a provenance manifest or a locality receipt there verifies it the same way here.

`id` is derived from the chat completion id: `chatcmpl-abc` yields `resp_abc` and item id `msg_abc`, so a `resp_…` in a caller's logs traces back to the `chatcmpl-…` the gateway recorded for the same generation.

`status` follows the finish reason. `length` reports `incomplete` with `incomplete_details.reason: "max_output_tokens"`; `content_filter` reports `incomplete` with `reason: "content_filter"`; anything else reports `completed`. A generation that faulted reports `failed` and describes the cause in `error`. An output item is only ever `completed` or `incomplete` — a failure is reported on the response, not on the item.

`store` is always `false`. No response is retained, so reporting `true` would advertise a `previous_response_id` follow-up this gateway refuses.

A streamed request emits named SSE events rather than `chat.completion.chunk` frames. Every event carries `type` and a monotonic `sequence_number` starting at 0:

| Event | Payload |
|-------|---------|
| `response.created` | `response` — the object with `status: "in_progress"` and an empty `output`. |
| `response.in_progress` | Same object. |
| `response.output_item.added` | `output_index`, `item` with `status: "in_progress"` and empty `content`. |
| `response.content_part.added` | `item_id`, `output_index`, `content_index`, `part`. |
| `response.output_text.delta` | `item_id`, `output_index`, `content_index`, `delta`, `logprobs`. One per token. |
| `response.output_text.done` | The accumulated `text`. |
| `response.content_part.done` | The completed `part`. |
| `response.output_item.done` | The completed `item`. |
| `response.completed` / `response.incomplete` / `response.failed` | `response` — the full object, same as the non-streaming body. |

There is no `data: [DONE]` sentinel: the terminal event is the terminator. The four opening events are withheld until the first chunk arrives, because that chunk carries the served model id and the completion id the response object is keyed on — emitting `response.created` earlier would name the model the caller asked for rather than the one that answered. A transport that ends before the generation does still gets a terminal event: `response.failed` when the connection faulted, `response.incomplete` when it closed cleanly mid-generation.

Reconnection runs over the same cursor store as the chat route. Each Responses event carries the `id:` line of the chat frame it was reframed from, so a client reconnecting with `Last-Event-ID` lands on the same cursor described in [Resume](#resume). The replayed chat frames are reframed by a fresh framer, so the resumed connection opens with its own `response.created` and its `sequence_number` restarts at 0 — the event ids are the shared cursor, the sequence numbers are per-connection. A stream whose generation already finished replays and then closes on a terminal `response.completed` / `response.incomplete` event, since there is no `[DONE]` to synthesize.

Anything the chat body has no home for is refused by name rather than dropped, so a caller is never billed for a completion that quietly ignored the ask. `previous_response_id`, a non-empty `tools`, and a `tool_choice` asking for anything other than `none` each return a 400 naming what was refused — see [Errors](#errors).

`/v1/completions` is not served. The Responses and chat-completions shapes cover the surface.

### Resume

Streams support reconnection via the SSE `Last-Event-ID` header. Every event's `id` is `<completion_id>:<seq>`; a reconnecting client sends `Last-Event-ID: <completion_id>:<seq>` and the node replays buffered chunks with a higher sequence number, synthesizing `[DONE]` if the stream already finished. The buffer is in-memory and expires per `data_policy.stream_resume_buffer_secs`.

### Streaming failover

The `Last-Event-ID` resume above covers a dropped *client* connection. When the drop is on the *provider* leg — the gateway is proxying a network model and the serving provider dies mid-generation — the gateway continues the stream on a different provider without a visible restart.

The gateway captures the sampling state as it forwards tokens: the original messages, the sampling parameters (`seed`, `temperature`, `top_p`, `max_tokens`), and the assistant text emitted so far. On a mid-stream drop or stall it selects another provider serving the same model, re-sends the request with the emitted text appended as a trailing assistant prefix and `continue_final_message: true`, and streams the continuation into the same SSE. Because the seed and parameters travel with the request, the new provider re-prefills the identical prefix and resumes sampling from the same distribution.

No KV-cache bytes cross the wire — the receiving provider re-computes the prefix from the emitted text. Failover is a bounded single retry: if the continuation provider also drops, the gateway penalizes it and ends the stream. Pin `seed` in the request for byte-identical continuation; without it the runtime default seed is used and captured.

### Audio transcriptions

`POST /v1/audio/transcriptions` serves speech recognition over any transcriber loaded into this node's audio runtime — Moonshine v2, Distil-Whisper, Whisper-large-v3-turbo, Parakeet-TDT-0.6B-v3, or Canary-1B-Flash. Load one with `tenzro_loadAudioModel` and list what is loaded with `tenzro_listAudioModels`. The request is `multipart/form-data`, matching the OpenAI wire shape, so an unmodified OpenAI SDK client reaches the runtimes without a Tenzro-specific client.

| Form field | Type | Default | Notes |
|------------|------|---------|-------|
| `file` | file | — | Required. The audio bytes. The body ceiling on this route is 128 MiB. |
| `model` | string | — | Required. A catalog entry id from `tenzro_listAudioCatalog`. |
| `language` | string | — | Source-language hint. Blank or whitespace-only is treated as absent rather than sent as an empty hint. |
| `response_format` | string | `json` | One of `json`, `text`, `verbose_json`, `srt`, `vtt`. |
| `temperature` | float | — | Decoder temperature. Omitted leaves the runtime default. |
| `timestamp_granularities` | string | — | `segment`. Also read from `timestamp_granularities[]`, the array spelling OpenAI SDKs send. |

`verbose_json`, `srt` and `vtt` render per-segment time ranges, so requesting any of them makes the runtime emit segment timestamps whether or not `timestamp_granularities` asked for them — the body cannot be built without them.

Fields the transcribe configuration has no home for are refused by name rather than dropped, so a caller is never billed for a request whose instructions were silently ignored. `timestamp_granularities: "word"` is refused because the runtimes emit segment-level ranges only, a non-empty `prompt` is refused because the decoders take no text conditioning on this route, and any other form field is refused as unknown — see [Errors](#errors).

The response shape follows `response_format`:

- `json` — `{"text": "…"}`.
- `text` — the transcript as a bare `text/plain` body.
- `verbose_json` — `task`, `language`, `duration`, `text`, and `segments[]` where each segment carries `id`, `start`, `end` and `text`. `duration` is the largest segment end time.
- `srt` — a SubRip body as `application/x-subrip`, with `HH:MM:SS,mmm` timecodes and 1-based cue numbers.
- `vtt` — a WebVTT body as `text/vtt`, with `HH:MM:SS.mmm` timecodes under a `WEBVTT` header.

A model that returns no time ranges cannot produce a subtitle body, so `srt` and `vtt` return a 400 naming the model and pointing at `json` or `text` instead.

### Image generations

`POST /v1/images/generations` serves text-to-image over the media-generation job queue. The queue is asynchronous: the route posts a job, announces it on `tenzro/media-gen`, waits for a worker to carry it to a terminal status under a bounded deadline, then fetches the rendered bytes and returns them base64-encoded. Admission, pricing and provenance are the same code path `tenzro_mediaGen_postJob` uses — this route adds a wire shape, not a second execution path.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `model` | string | — | Required. A catalog entry id from `tenzro_mediaGen_listCatalog`. Unlike OpenAI's optional default, this is required: a node serves whatever pipelines its operators enrolled workers for, so there is no single model to fall back to. |
| `prompt` | string | — | Required. |
| `size` | string | the model's default | `WIDTHxHEIGHT`. The longest side may not exceed what the catalog entry is trained for. |
| `n` | uint | 1 | Rejected unless `1` — one job renders one artifact, and fanning one request into several would hide the multiplier. |
| `response_format` | string | `b64_json` | Only `b64_json` is served. Rendered bytes live in the content-addressed media store, not behind a hosted URL. |

Tenzro extensions ride on the same body; OpenAI SDKs pass unknown fields through unchanged.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `requester_did` | string | — | Required. The identity the job is posted under. |
| `requester_address` | string | — | Required. Hex address the job's price is charged against. |
| `max_price` | string | this node's quote | Price ceiling in attoTNZO, decimal. The default is exactly the figure admission compares against. |
| `negative_prompt` | string | — | For pipelines that take one. |
| `steps` | uint | the catalog entry's reference figure | Denoising steps. |
| `guidance_scale` | float | the catalog entry's reference figure | Classifier-free guidance scale. |
| `seed` | uint | — | Left unset, the worker picks one and reports it on the receipt. |
| `wait_seconds` | uint | 300 | How long to hold the connection open. Capped at 300. |

`requester_did` and `requester_address` are required because nothing on an HTTP request carries an authenticated Tenzro principal — the payment gate verifies a credential but does not export the payer. The queue binds every job to the identity that posted it: that identity owns the price ceiling, is the only party that can cancel the job, and is who settlement charges. Substituting the node's own address would bill the operator for a stranger's render and leave the requester unable to cancel it.

`job_id` is derived by the runtime from the spec contents, so it is not a request field. Whether a job splits its denoising schedule across two experts is read from the catalog, never from the request.

`quality`, `style` and `user` are refused by name: the diffusion pipelines take no such control, and `steps` and `guidance_scale` are the knobs that exist.

A completed render returns the OpenAI shape plus a `tenzro` block carrying the receipt:

```json
{
  "created": 1780560000,
  "data": [{ "b64_json": "iVBORw0KGgo…", "revised_prompt": null }],
  "tenzro": {
    "job_id": "mgen_7c1f…",
    "model": "flux-schnell",
    "output_mime": "image/png",
    "output_hash": "0x9a3e…",
    "seed_used": 1024,
    "worker_did": "did:tenzro:machine:…",
    "generation_time_ms": 4180,
    "price_paid": "820000000000000"
  }
}
```

`revised_prompt` is always `null` — the prompt reaches the worker as sent.

The route re-reads the job status every 250 ms. If the deadline lapses before a worker finishes, the response is a **504** naming the `job_id`: the render is not abandoned, and the caller polls `tenzro_mediaGen_getJob` and then `tenzro_mediaGen_fetchOutput` for the bytes. A 2xx would be the wrong signal there — an OpenAI SDK client reads any 2xx as a rendered image and would fail parsing a body that carries a job id instead of `data[]`.

### Image edits

`POST /v1/images/edits` serves image-to-image over the same job queue. The request is `multipart/form-data`, matching the OpenAI wire shape for this route. The reference image is published into the content-addressed media store before the job is posted, so the worker fetches it by hash rather than receiving it inline, and the hash appears on the receipt as `input_image_hash`.

| Form field | Type | Default | Notes |
|------------|------|---------|-------|
| `image` | file | — | Required. The reference bytes. Also read from `image[]` and `images[]`, the array spellings OpenAI SDKs send for a single reference. |
| `prompt` | string | — | Required. |
| `model` | string | — | Required. A catalog entry id from `tenzro_mediaGen_listCatalog`. |
| `n` | uint | 1 | Rejected unless `1`. |
| `response_format` | string | `b64_json` | Only `b64_json` is served. |
| `strength` | float | the pipeline's default | How far the edit may travel from the reference image. |
| `size` | string | the model's default | `WIDTHxHEIGHT`, bounded by the catalog entry. |

`requester_did`, `requester_address`, `max_price`, `negative_prompt`, `steps`, `guidance_scale`, `seed` and `wait_seconds` behave exactly as on [Image generations](#image-generations), including the requirement that the first two be present.

The pipeline is fixed by the route, never by the body: this path is image-to-image whatever a request field claims. Letting a field override it would let a caller reach a pipeline the route was not priced for.

Vendor controls the pipelines have no home for are refused by name rather than dropped:

| Field | Why |
|-------|-----|
| `mask` | Inpainting is a separate pipeline call. Serving a masked request as a whole-frame edit would answer a different question than the one asked. |
| `background` | The pipelines render opaque frames and have no alpha channel to make transparent. |
| `input_fidelity` | `strength` is the knob that exists for how far an edit may travel. |
| `output_format`, `output_compression` | The container is the worker's and is reported back as `output_mime`. |
| `stream`, `partial_images` | The queue reports a terminal receipt, not partial denoising steps. |
| `quality`, `style` | The pipelines take no such control; `steps` and `guidance_scale` do. |
| `user` | The job is bound to `requester_did`, an authenticated identity rather than a free-form label. |

A completed edit returns the generations shape with one extra receipt field:

```json
{
  "created": 1780560000,
  "data": [{ "b64_json": "iVBORw0KGgo…", "revised_prompt": null }],
  "tenzro": {
    "job_id": "mgen_4b82…",
    "model": "flux-kontext",
    "input_image_hash": "0x51c7…",
    "output_mime": "image/png",
    "output_hash": "0xd0f4…",
    "seed_used": 7,
    "worker_did": "did:tenzro:machine:…",
    "generation_time_ms": 6240,
    "price_paid": "1140000000000000"
  }
}
```

`input_image_hash` is the store hash of the reference the worker actually read, so one receipt names both sides of the edit.

### Video renders

`POST /v1/videos` serves video rendering. It is `multipart/form-data` and, unlike the two image routes, it is a **job resource**: the POST returns immediately with a `queued` video, the caller polls `GET /v1/videos/{id}` until it reports `completed`, then reads the bytes from `GET /v1/videos/{id}/content`. A render that takes minutes has no business holding a connection open for them, and this is the shape the vendor publishes for the route.

| Form field | Type | Default | Notes |
|------------|------|---------|-------|
| `prompt` | string | — | Required. |
| `model` | string | — | Required. A catalog entry id from `tenzro_mediaGen_listCatalog`. |
| `input_reference` | file | — | An optional reference image. Present selects image-to-video; absent selects text-to-video. |
| `seconds` | float | the catalog entry's default frame count | Clip length. Multiplied by `fps` to get the frame count, rounded, floored at one frame. Must be finite and above zero. |
| `size` | string | the model's default | `WIDTHxHEIGHT`, bounded by the catalog entry. |
| `fps` | uint | the catalog entry's figure | Frame rate. |

`requester_did`, `requester_address`, `max_price`, `negative_prompt`, `steps`, `guidance_scale` and `seed` behave as on the image routes. `user` is refused by name for the same reason. There is no `wait_seconds`: the route does not wait.

Presence of `input_reference` is what selects the pipeline, so a text-to-video model that receives a reference image is refused rather than served a request it cannot honour.

```json
{
  "id": "mgen_e93a…",
  "object": "video",
  "model": "wan-t2v",
  "status": "queued",
  "progress": 0,
  "created_at": 1780560000,
  "prompt": "a paper boat crossing a still pond",
  "size": "832x480",
  "seconds": "5",
  "tenzro": {
    "job_id": "mgen_e93a…",
    "kind": "text2video",
    "split": false,
    "last_update": 1780560000,
    "max_price": "9200000000000000"
  }
}
```

`status` maps the queue's own states onto the four the vendor shape defines:

| Queue state | `status` |
|-------------|----------|
| Pending, Claimed | `queued` |
| Running | `in_progress` |
| Completed | `completed` |
| Failed, Cancelled | `failed` |

`progress` is a checkpoint count rather than an interpolation — the queue knows which stage a job reached, not what fraction of its denoising schedule is done — so the figure steps rather than climbing: `0` while pending or claimed, `25` or `50` or `75` while running depending on whether the schedule split and whether the handoff happened, `100` on completion.

`expires_at` is omitted rather than guessed: the rendered bytes live in the content-addressed media store under their own hash and are not swept on a clock.

`seconds` is a string, and is `null` unless the spec carries both a frame count and a frame rate. A completed job adds `completed_at` and the receipt fields under `tenzro` — `output_mime`, `output_hash`, `output_bytes`, `seed_used`, `worker_did`, `generation_time_ms` and `price_paid`. A failed job adds an `error` object carrying the worker's message.

`GET /v1/videos/{id}/content` returns the clip with the worker's `Content-Type` and a `Content-Disposition` filename derived from the job id. Asking for it before the job completes is a **409** naming the current status and the endpoint to poll — an SDK client writes any 2xx body straight to a file, and a zero-length clip is harder to diagnose than a status code naming what to poll. A `variant` query other than `video` is refused: the pipelines render the clip itself, with no thumbnail or spritesheet derivative.

### Forecasts

`POST /v1/tenzro/forecasts` serves timeseries forecasting over any model loaded into this node's timeseries runtime. Load one with `tenzro_loadForecastModel` and list what is loaded with `tenzro_listForecastModels`.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `model` | string | — | Required. A loaded forecast model id. |
| `history` | array | — | Required, non-empty. Observations in time order. |
| `horizon` | uint | — | Required, at least 1. How many steps to forecast. |
| `quantiles` | array | the runtime's default levels | Quantile levels to return. |
| `frequency_seconds` | uint | — | Sampling interval of the history, for models that read one. |

```json
{
  "object": "forecast",
  "model": "timesfm-2.5",
  "point": [104.2, 106.8, 108.1],
  "quantiles": [[98.4, 104.2, 110.9], [99.1, 106.8, 114.2], [99.6, 108.1, 116.8]],
  "quantile_levels": [0.1, 0.5, 0.9],
  "generation_time_ms": 84
}
```

`point` is the median path. `quantiles` is one row per forecast step, each row ordered to match `quantile_levels`.

### Detections

`POST /v1/tenzro/detections` serves object detection over any model loaded into this node's detection runtime — the RF-DETR and D-FINE families. Load one with `tenzro_loadDetectionModel` and list what is loaded with `tenzro_listDetectionModels`.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `model` | string | — | Required. A loaded detection model id. |
| `image_base64` | string | — | Required. The image bytes base64-encoded. |
| `score_threshold` | float | 0.25 | Confidence floor. |

```json
{
  "object": "detection",
  "model": "rf-detr-base",
  "detections": [
    { "bbox": [412.0, 118.5, 688.2, 540.9], "label_id": 3, "score": 0.91 }
  ],
  "generation_time_ms": 61
}
```

`bbox` is `[x1, y1, x2, y2]` in pixels against the image as sent. Both families are NMS-free, so the returned boxes are the model's own output with no suppression pass applied.

### Segmentations

`POST /v1/tenzro/segmentations` serves promptable segmentation. A geometric prompt reaches the SAM 1 and SAM 2 runtime; a text prompt reaches the open-vocabulary SAM 3 runtime. Load them with `tenzro_loadSegmentationModel` and `tenzro_loadTextSegmentationModel`, and list what is loaded with `tenzro_listSegmentationModels` and `tenzro_listTextSegmentationModels`.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `model` | string | — | Required. A loaded segmentation model id. |
| `image_base64` | string | — | Required. The image bytes base64-encoded. |
| `prompts` | array | — | Geometric prompts — points and boxes. |
| `text_prompt` | string | — | A noun phrase, for the open-vocabulary runtime. |
| `box_prompt` | object | — | Narrows a `text_prompt` to a region. |
| `score_threshold` | float | 0.5 on the text path | Confidence floor. |

`prompts` and `text_prompt` name different runtimes holding different models, so exactly one of them is required and sending both is refused rather than resolved by precedence. `box_prompt` narrows a `text_prompt`; a geometric box travels as an entry in `prompts`, and sending `box_prompt` without a text prompt is refused as misplaced.

The two paths return different nouns, because a text prompt locates instances and returns a box alongside each mask while a geometric prompt is already given the location:

```json
// text_prompt
{ "object": "segmentation", "model": "sam3", "generation_time_ms": 240,
  "segmentations": [
    { "bbox": [88.0, 140.0, 502.0, 690.0], "score": 0.88,
      "width": 1024, "height": 1024, "mask_base64": "iVBORw0KGgo…" }
  ] }

// prompts
{ "object": "segmentation", "model": "sam2-large", "generation_time_ms": 190,
  "masks": [
    { "width": 1024, "height": 1024, "score": 0.96, "mask_base64": "iVBORw0KGgo…" }
  ] }
```

Masks travel base64-encoded. A 1024² mask as a JSON array of integers is roughly 3 MB of text for one artifact, and no vendor standard governs the noun, so nothing is lost by encoding it compactly.

### Video embeddings

`POST /v1/tenzro/video/embeddings` embeds a clip into a single vector. It is separate from `/v1/embeddings` because a clip arrives as one artifact and returns one vector plus a frame count, where the vendor's embeddings shape returns a `data[]` list with no room to report how much of the clip was consumed.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `model` | string | — | Required. A loaded video model id. |
| `video_base64` | string | — | Required. The clip bytes base64-encoded. |
| `normalize` | bool | `false` | L2-normalize the returned vector. |
| `frame_stride` | uint | even spacing | Keep every Nth decoded frame instead of spreading the samples across the clip. Still capped at the clip encoder's frame budget. |

```json
{
  "object": "video_embedding",
  "model": "clip-vit-l14-frames",
  "embedding": [0.014, -0.221],
  "dim": 768,
  "frames_consumed": 16,
  "generation_time_ms": 1420
}
```

The route is served but the catalog's three V-JEPA 2 entries cannot currently be loaded: the upstream `facebook/vjepa2-*` repositories carry `safetensors` only, with no ONNX export, so `tenzro_loadVideoModel` refuses them. They stay in the catalog so licence-tier gating, discovery RPCs, CLI listing and MCP enumeration report the options correctly. The working path is registering an already-loaded image encoder as a frame-wise encoder, which samples frames, embeds each one and mean-pools. Calling the route with nothing loaded returns a **400** naming the RPC that loads a model.

### Errors

Errors follow the OpenAI envelope: `{"error": {"message": …, "type": …, "code": …}}`.

| Status | `code` | Meaning |
|--------|--------|---------|
| 400 | `unsupported_n` | `n` was present and not `1`. On `/v1/images/generations` and `/v1/images/edits`, one job renders one artifact. |
| 400 | `model_not_loaded` | The model resolves to this node but is not currently serving. On `/v1/audio/transcriptions`, `/v1/embeddings` and the four `/v1/tenzro/…` routes, no runtime is loaded under that id; the message names both the RPC that loads one and the RPC that lists what is loaded. |
| 400 | `unsupported_content_part` | A message carries a content part the serving runtime cannot render: an `input_audio` or `file` part, or an `image_url` for a model that loaded no multimodal projector. The message names the part type. On `/v1/responses`, also an `input_image` that carries only a `file_id`. |
| 400 | `invalid_image_part` | An `image_url` part that is not a `data:` URI, or whose base64 payload does not decode. A serving node reads inlined bytes only. |
| 400 | `missing_input` | `/v1/responses` — `input` was absent or an empty array. `/v1/embeddings` — `input` was neither a non-empty string nor an array of strings. |
| 400 | `unsupported_encoding_format` | `/v1/embeddings` — an `encoding_format` other than `float`. |
| 400 | `unsupported_response_format` | `/v1/audio/transcriptions` — a `response_format` outside `json`, `text`, `verbose_json`, `srt`, `vtt`. `/v1/images/generations` and `/v1/images/edits` — anything other than `b64_json`. |
| 400 | `malformed_multipart` | The `multipart/form-data` body could not be parsed. Shared by `/v1/audio/transcriptions`, `/v1/images/edits` and `/v1/videos`. |
| 400 | `unreadable_form_field` | A form part's bytes could not be read. The message names the part. Shared by the three multipart routes. |
| 400 | `unknown_form_field` | A form field the route does not serve. The message names it. Shared by the three multipart routes — a part is refused rather than dropped, so a caller is never billed for a render that ignored an instruction it was given. |
| 400 | `missing_file` | `/v1/audio/transcriptions` — `file` was absent or carried no bytes. |
| 400 | `missing_model` | `model` was absent on `/v1/audio/transcriptions`, `/v1/images/edits` or `/v1/videos`. |
| 400 | `invalid_temperature` | `/v1/audio/transcriptions` — `temperature` was not a number. |
| 400 | `unsupported_timestamp_granularity` | `/v1/audio/transcriptions` — `word`, which the runtimes do not emit, or an unrecognized value. |
| 400 | `unsupported_prompt` | `/v1/audio/transcriptions` — a non-empty `prompt`. The decoders take no text conditioning on this route. |
| 400 | `timestamps_unavailable` | `/v1/audio/transcriptions` — `srt` or `vtt` was requested and the model returned no segment time ranges. |
| 400 | `unsupported_media_kind` | A media-generation route named a model that does not serve the pipeline the route implies. The message lists what it does serve. The kind comes from the route, never from the body. |
| 400 | `unsupported_image_control` | `/v1/images/generations` — `quality`, `style` or `user`. Use `steps` and `guidance_scale`. |
| 400 | `invalid_size` | A media-generation route was given a `size` that was not `WIDTHxHEIGHT`. |
| 400 | `resolution_exceeded` | A media-generation route was given a longest side beyond what the model is trained for. |
| 400 | `invalid_requester_address` | A media-generation route was given a `requester_address` that was not a readable hex address. |
| 400 | `invalid_max_price` | A media-generation route was given a `max_price` that was not a decimal attoTNZO amount. |
| 400 | `job_not_admitted` | A media-generation route's queue refused the job. The message carries the runtime's reason, typically a price ceiling below the node's quote. |
| 400 | `unsupported_media_control` | `/v1/images/edits` or `/v1/videos` — a vendor control the pipelines have no home for. The message names the field and says why, rather than accepting it and rendering something else. |
| 400 | `invalid_number` | `/v1/images/edits` or `/v1/videos` — a numeric form field was not a number. The message names the field and echoes what arrived. |
| 400 | `missing_image` | `/v1/images/edits` — no reference image, under `image`, `image[]` or `images[]`. |
| 400 | `missing_prompt` | `/v1/images/edits` or `/v1/videos` — `prompt` was absent. |
| 400 | `missing_requester_did` | `/v1/images/edits` or `/v1/videos` — `requester_did` was absent. The job is bound to a DID, not to an opaque `user` string. |
| 400 | `missing_requester_address` | `/v1/images/edits` or `/v1/videos` — `requester_address` was absent. |
| 400 | `invalid_seconds` | `/v1/videos` — `seconds` was not a finite number above zero. |
| 400 | `invalid_fps` | `/v1/videos` — `fps` resolved to zero. |
| 400 | `unsupported_variant` | `GET /v1/videos/{id}/content` — a `variant` other than `video`. |
| 400 | `invalid_base64` | A `/v1/tenzro/…` route carried an inline image or clip that was not readable base64. The message names the field. |
| 400 | `missing_history` | `/v1/tenzro/forecasts` — `history` was absent or empty. |
| 400 | `invalid_horizon` | `/v1/tenzro/forecasts` — `horizon` below `1`. |
| 400 | `ambiguous_segmentation_prompt` | `/v1/tenzro/segmentations` — both `prompts` and `text_prompt`. They name different runtimes holding different models, so the route cannot pick one for the caller. |
| 400 | `missing_segmentation_prompt` | `/v1/tenzro/segmentations` — neither `prompts` nor `text_prompt`. |
| 400 | `misplaced_box_prompt` | `/v1/tenzro/segmentations` — `box_prompt` without a `text_prompt`. A geometric box travels as an entry in `prompts`. |
| 400 | `invalid_input_item` | `/v1/responses` — an `input` entry was not an object, or its `content` was neither a string nor an array of parts. |
| 400 | `unsupported_input_item` | `/v1/responses` — an `input` entry declared a `type` other than `message`. The message names the type. |
| 400 | `invalid_content_part` | `/v1/responses` — a content part was not an object, or an `input_file` carried neither `file_id` nor `file_data`. |
| 400 | `unsupported_previous_response_id` | `/v1/responses` — no response is retained, so prior turns must be replayed in `input`. |
| 400 | `unsupported_tools` | `/v1/responses` — a non-empty `tools` list. An absent or empty list is accepted. |
| 400 | `unsupported_tool_choice` | `/v1/responses` — a `tool_choice` asking for anything other than `none`. |
| 401 | — | Missing or invalid API key on a key-gated route. |
| 402 | — | Payment required on `/api/paid/chat/completions`. |
| 404 | `model_not_found` | Neither a local service instance nor a gossip-discovered network model matches `model`. On the three media-generation routes, no catalog entry carries that id. |
| 404 | `video_not_found` | `GET /v1/videos/{id}` or its `/content` — no video job under that id on this node. |
| 409 | `video_not_ready` | `GET /v1/videos/{id}/content` — the bytes were asked for before the job completed. The message names the current status and the endpoint to poll. An SDK client writes any 2xx body straight to a file, and a zero-length clip is harder to diagnose than a status code naming what to wait for. |
| 412 | `jurisdiction_not_satisfied` | No serving node declares a locality claim matching the pin. Raised before the first token on streaming requests. |
| 412 | `jurisdiction_receipt_unavailable` | `jurisdiction_receipt: "required"` and the local node has no claim or signer. |
| 429 | — | Rate limited. |
| 500 | `runtime_unavailable` | The node has no model runtime initialized. |
| 500 | `inference_error` | Local generation failed. |
| 500 | `transcription_error` | `/v1/audio/transcriptions` — the runtime faulted while decoding. |
| 500 | `embedding_error` | `/v1/embeddings` — the encoder faulted. |
| 500 | `forecast_error` | `/v1/tenzro/forecasts` — the timeseries runtime failed on this input. |
| 500 | `detection_error` | `/v1/tenzro/detections` — the detection runtime failed on this image. |
| 500 | `segmentation_error` | `/v1/tenzro/segmentations` — the segmentation runtime failed on this image. |
| 500 | `video_embedding_error` | `/v1/tenzro/video/embeddings` — the video runtime failed on this clip. |
| 500 | `job_vanished` | `/v1/images/generations` or `/v1/images/edits` — the job left the queue before reaching a terminal status. |
| 500 | `receipt_missing` | `/v1/images/generations` or `/v1/images/edits` — the job completed without a receipt, so there is nothing to fetch bytes against. |
| 500 | `catalog_entry_incomplete` | `/v1/videos` — the catalog entry declares neither an fps nor a default frame count, so the frame budget cannot be derived. |
| 502 | `provider_unreachable` | The serving provider could not be reached over iroh or its announced endpoint. |
| 502 | `provider_error` | The provider returned a non-success status; its status code is passed through when valid. |
| 502 | `completion_unreadable` | `/v1/responses` — the completion body could not be read before rewriting. |
| 502 | `completion_malformed` | `/v1/responses` — the completion body was not the JSON the rewrite expects. |
| 502 | `jurisdiction_receipt_unavailable` | `jurisdiction_receipt: "required"` and the provider returned no verifiable receipt. |
| 502 | `job_failed` | `/v1/images/generations` or `/v1/images/edits` — the job ended failed or cancelled. The message carries the worker's reason. |
| 502 | `output_unreachable` | `/v1/images/generations` or `/v1/images/edits` — the receipt named output the node could not fetch. |
| 504 | `render_timeout` | `/v1/images/generations` or `/v1/images/edits` — `wait_seconds` lapsed with the job still running. The message names the `job_id` to poll; the render continues. `/v1/videos` cannot raise this: it never waits, so a caller polls the job resource instead. |

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
    "prompt": "Write a Rust function that reverses a linked list.",
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
| `prompt` | string | no | — | The text the model will answer. Used only to place the request in a difficulty cluster (see below); it is not sent to any provider by this method. On `tenzro_chatByIntent` it is derived from `message`, or from the last user turn of `messages`, so it never has to be repeated. |
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
    "cluster": 7,
    "expected_error": 0.083,
    "reason": "use_case=code optimize=0.30 within budget; cheap tier meets quality_floor; scoring=measured cluster=7 expected_error=0.083"
  }
}
```

| Field | Type | Notes |
|-------|------|-------|
| `model_id` | string | The selected model. |
| `tier` | string | `cheap` or `strong` — the quality tier of the selected model. |
| `estimated_cost` | string (u128) | Estimated cost of the call in wei, given `est_input_tokens`/`est_output_tokens` at the selected model's price. String for the same range reason as `budget`. |
| `fallback_chain` | array of string | Ordered alternate `model_id`s to try if the primary is unavailable at dispatch, best-first. |
| `cluster` | uint or null | The difficulty cluster the prompt was placed in. `null` when no `prompt` was supplied or the node has no embedding model loaded. Echo it back to `tenzro_recordRouteOutcome` so the outcome is attributed to the right cluster. |
| `expected_error` | float or null | The selected model's observed adverse-outcome rate in that cluster, in `[0.0, 1.0]`. `null` means the cluster has no observations yet and the decision was made on declared model metadata alone. |
| `reason` | string | Human-readable explanation of the selection. Its `scoring=` clause states which path was taken: `measured` (cluster has observations) or `declared`. |

Errors:

| Code | Meaning |
|------|---------|
| -32602 | Unknown `use_case`, malformed `budget`, or `optimize` outside `[0.0, 1.0]`. |
| -32000 | No catalog model satisfies the intent (budget too low, `quality_floor` unmet, over the `payer_did` window cap, over the `payer_address` wallet balance, or empty catalog). |

#### How difficulty affects the selection

Two prompts with the same `use_case` are not equally hard, so routing on the declared use case alone over-serves easy prompts and under-serves hard ones.

When the intent carries a `prompt` and the node has a text-embedding model loaded, the prompt is embedded and placed in a difficulty cluster — an online clustering of the prompts this node has routed. Selection then scores each candidate on a blend of its normalized cost and its observed error rate *in that cluster*, weighted by `optimize`. A cheap model that keeps getting escalated on prompts like this one loses to a stronger model even though it is cheaper.

Clusters start empty. Until a cluster has observations, selection falls back to declared model metadata (parameter count, context window, capability tags) — the same behavior as before, and the same behavior on nodes with no embedding model loaded. Unmeasured model/cluster pairs carry a bounded exploration allowance so a model is not written off before it has been tried.

The loop closes through `tenzro_recordRouteOutcome`: report `resolved`, `escalated`, or `failed` against the `model_id` and `cluster` from the routing decision, and subsequent selections in that cluster account for it. Reporting is optional — routing works without it, it just stays on declared metadata.

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

It accepts every `tenzro_routeIntent` field plus the `tenzro_chat` simple-shape dispatch fields (`message`, `max_tokens`, `temperature`, `top_p`, `repeat_penalty`, `require_signed`, `caller_address`, `channel_id`, `channel_update_sig`). The response is the `tenzro_chat` response object with the resolved `model_id`, augmented with the full routing decision under `route` so the caller can see what the network picked. The prompt used for difficulty clustering is taken from `message` (or the last user turn of `messages`), so no extra field is needed.

Routing selects a model *and* a provider, and both are injected before dispatch: a caller-supplied `model` is dropped so intent routing stays authoritative, and the winning provider's address is set as the `provider` pin so the call settles against the offer that was actually scored. That is what makes the `settlement` object's `provider` and `provider_wei` refer to the same offer the `route` decision priced.

`tenzro_chatByIntent` records the outcome it can observe itself: a completed dispatch is recorded as `resolved`, a failed one as `failed`, against the cluster in the routing decision. Callers do not report those.

### `tenzro_recordRouteOutcome` — report an escalation

Reports how a routed call turned out, so per-cluster error rates reflect what happened rather than only what the catalog declares.

In practice this method carries `escalated` — the outcome only the caller knows, because it means the caller took the answer to a stronger model. `resolved` and `failed` are already recorded by `tenzro_chatByIntent` from the dispatch itself.

```json
{
  "jsonrpc": "2.0",
  "method": "tenzro_recordRouteOutcome",
  "params": {
    "model_id": "qwen3-8b",
    "cluster": 7,
    "outcome": "escalated"
  },
  "id": 1
}
```

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `model_id` | string | yes | The model that served the call — the `model_id` from the routing decision. |
| `cluster` | uint | yes | The `cluster` from the routing decision. A decision with `cluster: null` has nothing to report against. |
| `outcome` | string | yes | One of `resolved`, `escalated`, `failed`. |

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "retained": true,
    "model_id": "qwen3-8b",
    "cluster": 7,
    "outcome": "escalated"
  }
}
```

`retained: false` means the node has no difficulty index — it routes on declared metadata, so the report was accepted and discarded. That is not an error; reporting is advisory.

Errors:

| Code | Meaning |
|------|---------|
| -32602 | Missing `model_id`, missing or out-of-range `cluster`, or an `outcome` outside the three accepted values. |
| -32603 | This node has no model router configured. |
| -32000 | The difficulty index rejected the observation. |

### `tenzro_routeDifficultyStats` — inspect the difficulty index

Read-only view of the node's difficulty index: how many clusters it has discovered, how many prompts fell into each, and the per-cluster outcome counters for one model when `model_id` is supplied.

Centroids are not returned — they are high-dimensional vectors of no use to a caller and would dominate the response.

```json
{
  "jsonrpc": "2.0",
  "method": "tenzro_routeDifficultyStats",
  "params": { "model_id": "qwen3-8b" },
  "id": 1
}
```

`model_id` is optional. Without it the response carries only the cluster shape.

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "enabled": true,
    "cluster_count": 9,
    "capacity": 64,
    "embedding_dim": 768,
    "split_threshold": 0.72,
    "clusters": [
      { "cluster": 0, "prompts": 412 },
      { "cluster": 7, "prompts": 96 }
    ],
    "model_id": "qwen3-8b",
    "model_clusters": [
      {
        "cluster": 7,
        "resolved": 88,
        "escalated": 6,
        "failed": 2,
        "error_rate": 0.083
      }
    ]
  }
}
```

`enabled: false` (with `cluster_count: 0` and an empty `clusters`) means the node has no embedding model loaded, so every routing decision on it takes the declared-metadata path.

Errors:

| Code | Meaning |
|------|---------|
| -32603 | This node has no model router configured. |

### Cross-surface wrappers

All four operations are exposed on JSON-RPC, both MCP servers, A2A, the CLI, both SDKs, and the OpenClaw skill:

| Surface | Discovery | Discover + dispatch | Feedback | Index inspection |
|---------|-----------|---------------------|----------|------------------|
| JSON-RPC | `tenzro_routeIntent` | `tenzro_chatByIntent` | `tenzro_recordRouteOutcome` | `tenzro_routeDifficultyStats` |
| MCP (node) | `route_by_intent` tool | `chat_by_intent` tool | `record_route_outcome` tool | `route_difficulty_stats` tool |
| MCP (Python package) | `route_by_intent` tool | `chat_by_intent` tool | `record_route_outcome` tool | `route_difficulty_stats` tool |
| A2A | `inference` skill, intent-routing prompt | `inference` skill, intent chat prompt | `inference` skill, outcome prompt | `inference` skill, difficulty prompt |
| CLI | `tenzro inference route --use-case ...` | `tenzro inference route --use-case ... --message ...`, or `tenzro chat --use-case ...` | `tenzro inference record-outcome` | `tenzro inference difficulty-stats` |
| Rust SDK | `inference().route_intent(&params)` | `inference().chat_by_intent(&params, messages)` | `inference().record_route_outcome(...)` | `inference().route_difficulty_stats(...)` |
| TS SDK | `inference.routeIntent(params)` | `inference.chatByIntent(params)` | `inference.recordRouteOutcome(...)` | `inference.routeDifficultyStats(...)` |
| OpenClaw skill | `route_intent(...)` | `chat_by_intent(...)` | `record_route_outcome(...)` | `route_difficulty_stats(...)` |

The MCP `chat_completion` tool and the CLI `tenzro chat` command also make `model` optional: when `model` is omitted and a `use_case` is supplied, they resolve the model via the router before dispatching. That path resolves the offer at dispatch rather than pinning it to the scored price, so `chat_by_intent` is the one that guarantees the quoted price is the settled price. Supplying `model` explicitly skips routing.

Neither feedback nor index inspection is needed for routing to work. Outcomes the node can observe are recorded by `tenzro_chatByIntent` itself, whichever wrapper called it, so the feedback call carries `escalated` in practice. The stats call is an operator diagnostic.

Capability composition is one layer above routing and is exposed on JSON-RPC (`tenzro_orchestrate`), the node MCP server (`orchestrate` tool), the CLI (`tenzro inference orchestrate --intent ...`), and both SDKs (`orchestrate`).

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
- Routes mounted in `RpcServer::serve` (rpc.rs ~line 122): `POST /chat-stream` and `POST /v1/responses` are wired alongside `POST /v1/chat/completions` under both the gated and ungated branches. The gated branch goes through `tenzro_payments::middleware::payment_gate_handler` for HTTP 402 enforcement.
- `crates/tenzro-node/src/openai_responses.rs` — the Responses translation. `handle_openai_responses` in rpc.rs rewrites the request into a chat body, calls `handle_openai_chat_completions`, and rewrites the result back, so routing, settlement and provenance run once in the handler that owns them.

### Network forwarding

When a node receives `tenzro_chat` for a model it does not serve, it forwards to a peer per the existing logic in `handle_chat`. The forwarded payload **must** preserve the request shape — a rich-shape forward goes out as rich, not down-converted to simple. Down-conversion would silently drop tools, system prompts, and content blocks.

The forward travels over the `tenzro/infer` ALPN on the node's iroh endpoint. The serving peer is addressed by its iroh `EndpointId` (resolved via Pkarr — never by IP), which is published as the `iroh_endpoint_id` field on the model's endpoint record. Inspect it with `tenzro_listModelEndpoints` (or the MCP `list_model_endpoints` tool): a non-empty `iroh_endpoint_id` identifies the serving node; an empty string means the service is local-only. A response returned this way carries `location: "network"` and the serving `provider`.

### Billing

Cost calculation is identical for both shapes: `input_tokens × input_price + output_tokens × output_price`. Tool-use response tokens (the `tool_use` blocks themselves) count as output tokens. Cached input tokens are billed at a discounted rate (TBD; design says 10% of normal rate, matching Anthropic's prompt caching).

Settlement runs on the node the request arrived at, before the response is returned. With a `caller_address` and non-zero cost, that node either debits an open micropayment channel (when `channel_id` + `channel_update_sig` are supplied) or executes a direct on-chain transfer. A rejected debit or transfer fails the request with `-32023` and persists an unpaid-settlement marker keyed in `data.unpaid_key` — settlement failure is never a silent free inference. The outcome is reported in the response `settlement` field.

When the request is forwarded to a peer, the **gateway** settles the peer's leg rather than the serving provider doing it: the forwarded request carries no payer, and every node shares one ledger, so the node holding the payer relationship is the one that can move funds. Pricing for that leg comes from the announcement the routing decision scored, not from anything in the provider's response — a provider cannot re-price after serving. The provider's wallet is the `provider_address` on that announcement.

The split is a carve-out, not a surcharge. `NetworkCommissionRates::inference_commission_bps` of the quoted cost goes to the treasury and the remainder to the provider, so `commission_wei + provider_wei` equals the price the consumer was quoted. A developer margin (`app_id`) is the opposite direction: it is added on top of the network cost and routed to the app's wallet as `margin_wei`. The channel path reports `commission_wei: 0` because commission and margin are carved once at channel finalize rather than on every update.

Every completed generation is also recorded with the node's usage tracker under the completion id, which is what [`GET /v1/generation`](#generation-stats-lookup) reads back. A routed generation is recorded by the router as the response passes back through the gateway; one served from this node's own weights is recorded on the local path. A node with no payee address configured records nothing, because per-provider totals feed reward metering at epoch close and an unattributed record would distort it.

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
- **Rich shape, full round-trip**: spawn a test that sends a `messages` array including a `system` block, receives a `tool_use`, returns a `tool_result`, receives a final `text` answer. Asserts `stop_reason` transitions correctly.
- **Streaming**: SSE smoke test for both shapes — assert event counts and ordering.
- **Tool schema validation**: invalid `input_schema` (e.g., not a JSON Schema object) returns `-32602` at request time, not at response time.
- **Cross-shape isolation**: sending both `message` and `messages` is an error, not a silent precedence.
- **Network forwarding**: rich-shape request to a non-serving node forwards to a serving peer with the rich payload intact.
