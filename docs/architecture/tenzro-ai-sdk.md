# `tenzro-ai` SDK Design

**Status:** Design accepted (2026-05-06). Implementation in `sdk/tenzro-ai/`.

## 1. Purpose

`tenzro-ai` is the canonical TypeScript SDK for accessing AI on Tenzro Network. It is sibling to `tenzro-wallet`: both packages live in standalone GitHub repos, both consume `tenzro-sdk` for transport, both project a high-level developer-facing API over the node's JSON-RPC surface.

Audience is three classes of consumer, served by the same surface:

- **Apps** — server or browser code calling Tenzro inference end-to-end.
- **Human developers** — running ad-hoc inference from a script with one import.
- **Agents** — autonomous machine identities (TDIP `did:tenzro:machine:*`) calling inference under a delegation scope, paying with TNZO.

In-scope today:

- Discovery and inference across all seven modalities the node already serves: chat/text, forecast, vision, text embedding, segmentation, detection, audio (ASR), video.
- Provider routing (price / latency / reputation / weighted / TEE-required) over Tenzro's decentralized provider set.
- TDIP identity at the request boundary (humans + machines).
- TNZO-denominated payment (x402, MPP, channel, auto-select).
- Tool calling and a single-class `Agent` loop.
- Optional response verification (TEE attestation, Plonky3 STARK).

Deferred to follow-up waves: distributed training (Phase 9), advanced agentic orchestration beyond the single-class agent loop, durable execution (delegated to `tenzro_postTask` task marketplace).

## 2. Decision: shape and packages

`tenzro-ai` adopts the **Vercel AI SDK** shape, not the OpenAI Node SDK shape. Top-level async functions, `LanguageModelV2`-style provider interface, AsyncIterable streams, single `Agent` value, zod-first structured output. The Vercel AI SDK won the TypeScript AI DX race in 2025–2026; building anything else means re-fighting a decided fight.

Three packages, scoped under `@tenzro`:

| Package | Role | Runtime | Public surface |
|---|---|---|---|
| `@tenzro/ai` | Core SDK | Node ≥22, Bun, Deno, Cloudflare Workers, browsers | `generateText`, `streamText`, `generateObject`, `streamObject`, `embed`, `embedMany`, `embedImage`, `embedVideo`, `forecast`, `segment`, `detect`, `transcribe`, `imageTextSimilarity`, `tenzro()` provider factory, `discoverProviders`, `Agent`, `tool`, `verifyAttestation`, `verifyZkProof`, error classes |
| `@tenzro/ai-provider` | Provider authoring kit | Same | `LanguageModelV2`-shaped types, `defineProvider` helper, stream-part types — for anyone (incl. external Tenzro nodes) implementing a custom provider |
| `@tenzro/ai-react` | React bindings | Browser + RSC | `useChat`, `useCompletion`, `useObject` hooks over `streamText`/`streamObject` |

These are three published npm packages in a pnpm/turbo monorepo, mirroring the `tenzro-wallet` layout (`packages/wallet-kernel`, `packages/ui`).

## 3. Repo and dev-tree layout

Source of truth lives in the monorepo dev tree:

```
~/AI/tenzronetwork/sdk/tenzro-ai/
├── package.json                  # private workspace root
├── pnpm-workspace.yaml
├── turbo.json
├── biome.json
├── tsconfig.base.json
├── packages/
│   ├── ai/                       # @tenzro/ai (publishable)
│   ├── ai-provider/              # @tenzro/ai-provider (publishable)
│   └── ai-react/                 # @tenzro/ai-react (publishable)
└── docs/                         # repo-level README, examples
```

The package is developed in the monorepo first; the standalone GitHub mirror is published as a derived artifact via the established repo sync mechanism. Design and implementation happen entirely in the dev tree before any mirror push.

Tooling is identical to `tenzro-wallet`: pnpm 10.33.2, turbo 2.3.3, biome 1.9.4, TypeScript 5.7.3, vitest 4, ESM-only, Node ≥22. `tsconfig.base.json` carries `strict: true`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `verbatimModuleSyntax`. This is non-negotiable — every Tenzro TS package speaks the same dialect.

## 4. Relationship to existing SDKs

| SDK | Role after `tenzro-ai` ships |
|---|---|
| `tenzro-sdk` (Rust) | Unchanged. Carries `InferenceClient`, `ProviderClient` for Rust callers. |
| `sdk/tenzro-ts-sdk` (TS) | `InferenceClient` removed. The package keeps wallet/identity/agent/bridge/etc. clients; AI is no longer in scope. `tenzro-ai`'s core depends on `tenzro-sdk` (the npm package, which is `tenzro-ts-sdk`'s published name) for `RpcClient`, transport, and config. |
| `tenzro-wallet` | Unchanged. `tenzro-ai` consumes `WalletKernel` *optionally* via a `walletSigner(kernel)` adapter that projects the wallet's TDIP identity + signing into a `Signer` for inference. No coupling forced — apps without a wallet can pass any `Signer` implementation, or none at all (faucet-tier). |

This is the pre-launch hygiene rule applied at SDK level: one canonical AI surface, no parallel half-implementations. When `tenzro-ai` ships, `tenzro-ts-sdk`'s `InferenceClient` is deleted, not deprecated.

## 5. Public API — surface tour

### 5.1 Three lines to first token

```ts
import { generateText, tenzro } from '@tenzro/ai';

const { text } = await generateText({
  model: tenzro('llama-3.3-70b'),
  prompt: 'What is post-quantum cryptography?',
});
```

No identity, no payment — works against the Tenzro testnet faucet tier. Same shape as Vercel AI SDK's `generateText`. The `tenzro()` factory is the provider; `'llama-3.3-70b'` is a bare model ID, the router picks the provider.

### 5.2 Identity and payment

```ts
import { generateText, tenzro, walletSigner } from '@tenzro/ai';
import { WalletKernel } from 'tenzro-wallet';

const wallet = await WalletKernel.recover({...});
const signer = walletSigner(wallet);

const { text, attestation, paymentReceipt } = await generateText({
  model: tenzro('llama-3.3-70b', { strategy: 'reputation', requireTee: 'tdx' }),
  prompt: 'Summarize this contract.',
  signer,
  payment: { protocol: 'auto', maxPrice: { amount: 1_000n, currency: 'TNZO' } },
});
```

Identity flows as a `signer` argument (TDIP DID + hybrid Ed25519+ML-DSA-65). Payment is a request option that auto-selects x402 / MPP / channel based on the response 402 challenge. Verification metadata (`attestation`, `zkProof`) returns on the response when the provider supplied it.

### 5.3 Streaming

```ts
const result = await streamText({ model: tenzro('llama-3.3-70b'), prompt });
for await (const part of result.fullStream) {
  if (part.type === 'text-delta') process.stdout.write(part.text);
  if (part.type === 'reasoning-delta') /* render thinking */;
  if (part.type === 'tool-call') /* ... */;
}
```

`fullStream` is `AsyncIterable<TenzroStreamPart>` and matches Vercel AI SDK's `LanguageModelV2StreamPart` part-type union, with three Tenzro-specific additions (§7.2). Wire format is the node's existing `/chat-stream` SSE.

### 5.4 Multi-modal — modality-named functions

```ts
const { embedding } = await embed({ model: tenzro('qwen3-embed-4b'), value: 'hello world' });
const { embeddings } = await embedMany({ model: tenzro('qwen3-embed-4b'), values: docs });
const { embedding: imageEmb } = await embedImage({ model: tenzro('siglip2-large'), image: pngBytes });
const { predictions } = await forecast({ model: tenzro('timesfm-2.5-200m'), series, horizon: 24 });
const { masks } = await segment({ model: tenzro('sam-3'), image: pngBytes, prompts });
const { detections } = await detect({ model: tenzro('rf-detr-medium'), image: pngBytes });
const { text } = await transcribe({ model: tenzro('whisper-v3-turbo'), audio: wavBytes });
```

One function per first-class modality. Maps 1:1 to existing node RPCs (`tenzro_textEmbed`, `tenzro_imageEmbed`, `tenzro_forecast`, `tenzro_segment`, `tenzro_detect`, `tenzro_transcribe`, `tenzro_videoEmbed`). HuggingFace Inference's anti-pattern of dozens of method names on one client is rejected — only the seven first-class modalities get their own function.

### 5.5 Agents

```ts
import { Agent, tool, stepCountIs, hasToolCall } from '@tenzro/ai';
import { z } from 'zod';

const agent = new Agent({
  model: tenzro('llama-3.3-70b'),
  tools: {
    transferTnzo: tool({
      description: 'Transfer TNZO to a recipient',
      inputSchema: z.object({ to: z.string(), amount: z.bigint() }),
      execute: async ({ to, amount }) => wallet.transfer(to, amount),
      needsApproval: ({ amount }) => amount > 100n,
    }),
  },
  signer,
  payment: { protocol: 'auto', maxPrice: { amount: 5_000n, currency: 'TNZO' } },
  stopWhen: [stepCountIs(20), hasToolCall('settle')],
});

const result = await agent.run({ prompt: 'Pay vendor X 50 TNZO and confirm.' });
```

`Agent` is a single value, not a class hierarchy. `stopWhen` is an array of composable predicates lifted directly from AI SDK 6's `stopWhen` API. `tool({needsApproval})` integrates with TDIP `DelegationScope` enforcement: if approval is required, the signer is asked to sign a separate authorization, which can route to a UI prompt, a session-key auto-approve, or fail fast.

### 5.6 Verification

```ts
import { verifyAttestation, verifyZkProof } from '@tenzro/ai';

const { text, attestation, zkProof } = await generateText({...});
if (attestation) await verifyAttestation(attestation);
if (zkProof) await verifyZkProof(zkProof);
```

Both verifiers are top-level functions over the response payload. Default policy is `verify: 'lazy'` (provider commitment recorded, async verification). `verify: 'eager'` blocks on verification before resolving. `verify: 'off'` skips entirely.

## 6. Provider model

The `tenzro()` factory returns a `LanguageModelV2`-conformant model. Internally it wraps:

- A `RpcClient` (from `tenzro-sdk`) pointed at `https://rpc.tenzro.network` by default.
- A `discoverProviders` cache keyed on `(modality, region, requireTee)` with TTL, refreshed on `tenzro/models` gossipsub events when running in-network.
- A `routing` strategy that picks one Tenzro provider per request and falls back across the discovered set on transport / 402-over-budget / TEE-attestation-fail / quality errors.
- A `signer` and `payment` inherited from the call site or pre-bound on the factory.

Two model-ID forms:

- `'llama-3.3-70b'` — bare, router selects.
- `'tenzro:did:tenzro:machine:abc123/llama-3.3-70b'` — pinned to provider DID. Router does not re-shop.

`@tenzro/ai-provider` exposes the `LanguageModelV2` shape so external authors (running their own GGUF/ONNX serving stack) can publish a Tenzro-compatible provider package. This is how Vercel AI SDK's ecosystem grew (`@ai-sdk/openai`, `@ai-sdk/anthropic`, ...) — same playbook, different provider economy.

## 7. Tenzro-specific deltas from Vercel AI SDK

The Vercel AI SDK assumes API-key auth, billed-elsewhere economics, and a small static provider list. Tenzro inverts all three. The deltas:

### 7.1 `signer` instead of `apiKey`

Every top-level function accepts `signer?: Signer`. `Signer` is a single-method interface:

```ts
interface Signer {
  did(): string;
  sign(preimage: Uint8Array): Promise<HybridSignature>;
}
```

Canonical preimage:

```
SHA-256("tenzro/inference/req"
        || sha256(model_id_utf8)
        || sha256(canonical_messages_json)
        || nonce_le_8
        || timestamp_le_8)
```

Domain tag follows the project rule (no version segment in Tenzro-owned strings — the protocol changes the tag if the canonicalization changes). The hybrid signature is Ed25519 + ML-DSA-65, attached as `Authorization: TenzroSig <hex>`. `walletSigner(kernel)` adapts a `WalletKernel` to this interface; alternative signer implementations (passkey-only for human users, hardware key for high-value agents) are pluggable without changing the SDK surface.

### 7.2 Stream-part extensions

In addition to AI-SDK-6 part types (`text-delta`, `reasoning-delta`, `tool-call`, `tool-call-delta`, `tool-result`, `error`, `finish`):

- `tenzro-attestation` — TEE attestation envelope from the provider.
- `tenzro-zk-proof` — Plonky3 STARK proof bytes + circuit ID.
- `tenzro-payment-receipt` — settlement receipt (channel update / x402 settlement / MPP receipt).

These appear inline in the stream so a UI can render verification badges in real time. `useChat` (in `@tenzro/ai-react`) recognizes them as known part types.

### 7.3 Inline payment

```ts
type PaymentSpec = {
  protocol: 'x402' | 'mpp' | 'channel' | 'auto';
  maxPrice: { amount: bigint; currency: 'TNZO' | 'USDC' | 'USDT' };
  channelId?: ChannelId;  // when protocol === 'channel'
};
```

The SDK never holds funds. On HTTP 402, it parses the challenge, dispatches to the bound signer/wallet for a payment credential, retries the request, and surfaces the receipt on the response. `protocol: 'auto'` inspects the 402 challenge type and picks: `x402` for stateless one-shots, `mpp` for streaming sessions (the SDK opens a session on the first call, reuses on subsequent calls in the same `streamText` lifetime), `channel` if a `channelId` is provided. This is the same loop as Coinbase's `x402-fetch`, generalized over Tenzro's three protocols.

### 7.4 Discovery as a real call

`discoverProviders({ modality, requireTee?, maxPrice?, minReputation?, region? }) → Promise<TenzroProvider[]>`

Hits the node JSON-RPC: `tenzro_listModelEndpoints`, then fans out to `tenzro_listModels` and `tenzro_getProviderReputation` to enrich. Cached in-process with a 30-second TTL. Apps that want full control call `discoverProviders` and then `tenzro({ providers: [...] })`; apps that just want it to work call `tenzro('llama-3.3-70b')` and let the factory do discovery on first use.

### 7.5 Routing strategy at the boundary

```ts
tenzro('llama-3.3-70b', {
  strategy: 'reputation',         // 'price' | 'latency' | 'reputation' | 'weighted'
  requireTee: 'tdx',              // 'tdx' | 'sev-snp' | 'nitro' | 'nvidia-cc' | 'any'
  maxFallbacks: 3,
  region: 'us-central',
});
```

Mirrors OpenRouter's provider-selection ergonomic but executes in the SDK against Tenzro's `InferenceRouter` strategies (`price`, `latency`, `reputation`, `weighted`), which already exist in `crates/tenzro-model/`. The router runs *in the SDK*, not on the node — a provider's selection decision is the consumer's, not the network's.

### 7.6 Verification is composable

Mainstream SDKs have no concept of verifying responses. Tenzro providers can attach TEE attestations and Plonky3 STARK proofs. The SDK keeps `verifyAttestation` and `verifyZkProof` as separate top-level functions so the user opts in. This is the wedge: every other AI SDK trusts the provider; ours allows checking.

## 8. Errors, retries, observability

Error taxonomy (typed classes, all extend `TenzroAIError`):

| Class | When |
|---|---|
| `RateLimitError` | Provider returned 429 |
| `ModelUnavailableError` | Model not loaded by any discovered provider |
| `ContextTooLongError` | Input exceeds model context window |
| `ContentModerationError` | Provider refused on policy grounds |
| `PaymentRequiredError` | 402 returned and SDK could not satisfy (no signer, no wallet, over `maxPrice`) |
| `ProviderUnreachableError` | Network or transport failure on a specific provider |
| `AttestationFailedError` | TEE attestation verification failed |
| `ZkProofFailedError` | STARK verification failed |
| `DelegationViolationError` | Signer refused — request exceeds DID's delegation scope |

Retries: exponential backoff with jitter on `RateLimitError` and `ProviderUnreachableError`. Failover (try next provider in the discovered set) on `ModelUnavailableError`, `ProviderUnreachableError`, `AttestationFailedError`, and `PaymentRequiredError` when a different provider quotes a price within `maxPrice`. No retry on `ContentModerationError`, `ContextTooLongError`, `DelegationViolationError`.

Observability: OpenTelemetry-first, configurable via `experimental_telemetry: { isEnabled, recordInputs, recordOutputs }` (matches Vercel AI SDK's existing `experimental_telemetry` shape exactly). Default span names use the `tenzro.ai.*` namespace. Langfuse / Helicone / Arize integration is "configure your OTel collector"; we do not ship vendor SDKs.

## 9. What lives where

| Concern | Lives in | Why |
|---|---|---|
| Model loading, GGUF/ONNX runtimes, modality dispatch | `crates/tenzro-model/` (node) | Server-side; SDK never touches model files |
| `InferenceRouter` strategies (price/latency/reputation/weighted) | `crates/tenzro-model/` + duplicated in SDK for client-side fallover | Node uses it for cross-provider routing within its own provider stack; SDK uses it across the discovered network |
| Per-provider pricing, reputation, scheduling | Node (gossipsub + RocksDB) | Authoritative on-network state |
| 402 challenge issuance, MPP session lifecycle, settlement | Node middleware (`crates/tenzro-payments/`) | SDK only consumes; never originates |
| TDIP identity registry, delegation scopes | Node + `tenzro-wallet` | SDK consumes via `Signer` interface; never owns |
| Signing canonicalization, hybrid Ed25519+ML-DSA-65 | `tenzro-wallet` | SDK delegates; reuses one hybrid signer impl across the ecosystem |
| Streaming wire format (`/chat-stream` SSE) | Node | SDK adapts SSE → AsyncIterable |
| OpenAI-compatible adapter (`/v1/chat/completions`) | Node already serves this | SDK does not need its own — but ships an adapter so users with existing `openai` clients can point them at `https://rpc.tenzro.network/v1` and they Just Work, with payment via header |
| Retry, backoff, failover, error classes | SDK | Pure client-side concern |
| Provider discovery and TTL cache | SDK | Pure client-side concern |
| `Agent` loop (`stopWhen`, `prepareStep`, tool execution) | SDK | Client-side orchestration; never on the node |
| Durable agent execution | Node task marketplace (`tenzro_postTask`) — SDK exposes `runDurable(agent, input)` adapter | Durability requires server-side state; SDK delegates |

## 10. Open questions

- **`exactOptionalPropertyTypes` interop with `tenzro-sdk`.** The npm-published `tenzro-sdk` was authored before `exactOptionalPropertyTypes` was strict in the workspace. If its `.d.ts` files use `T | undefined` in places where the wallet-kernel base config expects `T?`, the SDK will need internal adapter types. Verify on first compile.
- **WebCrypto support for ML-DSA-65 in browsers.** Hybrid Ed25519+ML-DSA-65 signing is straightforward in Node; browsers and Cloudflare Workers need a WASM ML-DSA-65 impl. The hybrid signer ships separately as `@tenzro/signer` (or as part of `tenzro-wallet`'s extracted signing driver) — the SDK takes the `Signer` interface; how the browser implementation works is `tenzro-wallet`'s problem.
- **`runDurable` API shape.** Submitting an agent run to `tenzro_postTask` and reattaching to its result stream needs a richer return type than `agent.run()`. Likely `agent.runDurable()` returns `{ taskId, stream, cancel }` where `stream` is the same `AsyncIterable<TenzroStreamPart>` reattached from the task marketplace. Detailed shape TBD.
- **Reasoning-token attestation.** When a provider streams `reasoning-delta` parts (Claude extended-thinking-style), does the TEE attestation cover the reasoning trace, or only the final answer? Provider-implementation-dependent — surface as `attestation.scope: 'final-only' | 'full-trace'` on the response part.
- **Region routing.** `region` filter requires providers to publish a region tag on registration. Not present on `tenzro_registerProvider` today. Either extend that RPC (additive, safe) or compute region heuristically from latency probes; likely the former.

## 11. Implementation milestones

Tracked as tasks in the active session:

1. Workspace + tooling scaffold (mirrors `tenzro-wallet` exactly).
2. Core types (model, provider, signer, payment, error taxonomy, stream parts).
3. RPC port + provider discovery + TTL cache.
4. Signer interface + payment middleware (x402, MPP, channel, auto).
5. `generateText`, `streamText`, `generateObject`, `streamObject` over `/chat-stream`.
6. Multi-modal top-levels (`embed`, `embedImage`, `forecast`, `segment`, `detect`, `transcribe`, `embedVideo`).
7. `Agent` + `tool` + verification helpers.
8. `@tenzro/ai-react` `useChat` / `useCompletion` / `useObject`.
9. Tests (vitest), README, examples, OpenAI-compat adapter recipe.
10. Remove `InferenceClient` from `sdk/tenzro-ts-sdk` (pre-launch hygiene; one canonical AI surface).
