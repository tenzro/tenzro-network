# Speculative Decoding for Tenzro Inference

**Status:** Catalog metadata shipped (2026-05-06). Runtime integration **deferred** — see §5.

## 1. Background

Speculative decoding pairs a heavyweight target model with a small drafter that proposes N future tokens at once; the target verifies the draft in parallel and accepts the longest matching prefix. Best case is ~2–3× tokens-per-second with no quality change.

Two sources for drafters today:

- **Generic same-family pairing.** A small GGUF from the same family as the target, with a matching tokenizer (Qwen3-0.6B for Qwen3-32B, Qwen3.5-0.8B for Qwen3.6-27B). Mature in `llama.cpp` for years, extended for Qwen3.5/3.6 via PR ggml-org/llama.cpp#19493.
- **Native MTP heads.** The target model itself produces multi-token predictions through architecture-aware MTP heads (Gemma 4's "assistant" drafters, Nemotron-3-Super, DeepSeek V3/R1). llama.cpp PR ggml-org/llama.cpp#22673 adds plumbing for this; unmerged at time of writing, and the maintainer has flagged that Gemma 4 specifically needs additional architecture work (shared KV cache + clustering) beyond what the PR provides.

Tenzro's current inference path is `llama-cpp-2` 0.1.143 (Rust safe wrapper) over `llama-cpp-sys-2` (FFI to `libllama`), single `LlamaModel` + single `LlamaContext` per served model — see `crates/tenzro-model/src/runtime.rs`.

## 2. Catalog metadata (shipped)

`HfModelEntry` carries an optional `drafter_id: Option<String>`. When set, it points to another catalog entry — itself a regular downloadable GGUF — that is the recommended speculative drafter for this target. Six pairings are wired today:

| Target | Drafter | Source |
|---|---|---|
| `qwen3-32b` | `qwen3-0.6b` | `unsloth/Qwen3-0.6B-GGUF` |
| `qwen3.6-27b` | `qwen3.5-0.8b` | `unsloth/Qwen3.5-0.8B-GGUF` |
| `mistral-small-3.1-24b` | `mistral-small-3.1-draft-0.5b` | `alamios/Mistral-Small-3.1-DRAFT-0.5B-GGUF` |
| `mistral-small-3.2-24b` | `mistral-small-3.1-draft-0.5b` | `alamios/Mistral-Small-3.1-DRAFT-0.5B-GGUF` |
| `gemma4-e2b` | `gemma4-e2b-it-assistant` | `Radamanthys11/Gemma-4-E2B-it-assistant-GGUF` |
| `gemma4-31b` | `gemma4-31b-it-assistant` | `Radamanthys11/Gemma-4-31B-it-assistant-GGUF` |

Two integrity tests in `catalog::tests`:

- `test_drafter_ids_resolve` — every `Some(drafter_id)` resolves, drafters don't nest, drafter is smaller than target.
- `test_known_drafter_pairings` — locks the six pairings above so a careless edit can't silently regress them.

Deliberately not wired (with reasoned comments in source):

- `qwen3.6-35b-a3b` — `qwen3.5-0.8b` would be vocab-matched, but the 3B-active-path MoE is **net-negative** on consumer GPUs (RTX 3090 benchmark in [thc1006/qwen3.6-speculative-decoding-rtx3090](https://github.com/thc1006/qwen3.6-speculative-decoding-rtx3090)). Verify cost outweighs draft savings.
- `gemma4-e4b`, `gemma4-26b-a4b` — Google has the safetensors at `google/gemma-4-{E4B,26B-A4B}-it-assistant`, but no community GGUF conversion exists yet on HF as of 2026-05-06.

## 3. Runtime integration — what it would take

The hard fact from researching `llama-cpp-2` 0.1.143 source and llama.cpp's `common/speculative.h`:

**`llama-cpp-2` 0.1.143 has zero speculative-decoding API.** No public symbol contains `speculative`, `draft`, `Spec`, or `Draft`. The crate does not re-export the underlying `llama_cpp_sys_2` FFI module. `llama_cpp_sys_2` 0.1.143 itself exposes the `libllama` primitives (`llama_decode`, `llama_get_memory`, `llama_memory_seq_rm`, `llama_state_seq_*_ext`, `llama_model_get_vocab`, `llama_vocab_n_tokens`, `llama_vocab_get_text`) but not the orchestration layer.

The orchestration layer — `common_speculative_init`, `common_speculative_begin`, `common_speculative_draft`, `common_speculative_accept`, `common_speculative_free`, `common_speculative_are_compatible` — lives in `common/speculative.{h,cpp}` of llama.cpp, which compiles to a separate static helper `libllama-common`. `libllama-common` depends on `libllama` but is not part of it. `llama-cpp-sys-2`'s build.rs links `libllama` only.

A search of `utilityai/llama-cpp-rs` issues and PRs returns **zero** open or merged work for speculative decoding bindings. Upstream isn't already on this.

So the runtime slice has three viable paths, each with real cost:

### 3.1 Option A — Reimplement the speculative loop in Rust over `libllama` primitives

Reach: `llama_decode`, `llama_memory_seq_rm`, `llama_state_seq_*_ext`, `llama_get_memory`, vocab-introspection helpers — all in `libllama`, all reachable through `llama_cpp_sys_2`'s FFI.

What we own:
- The speculative loop itself (~150 LoC of Rust over unsafe FFI).
- A reimplementation of `common_speculative_are_compatible` (vocab-type equality + `|n_vocab_tgt − n_vocab_dft| ≤ SPEC_VOCAB_MAX_SIZE_DIFFERENCE` + per-token text equality from `SPEC_VOCAB_CHECK_START_TOKEN_ID` upward) — ~50 LoC.
- KV-cache state save/restore on rejection.
- Unsafe FFI helpers for the calls `llama-cpp-2`'s safe wrapper doesn't expose. Need to either fork `llama-cpp-2`, depend on `llama-cpp-sys-2` directly alongside the safe wrapper, or upstream new accessors.

Total surface: 400–600 LoC of `unsafe`-touching Rust. Every llama.cpp change to KV-cache-state semantics becomes a porting exercise we own. The C++ source we're tracking is not committing to a stable interface for these primitives — they get refactored.

### 3.2 Option B — Bind `common_speculative_*` directly via `bindgen`

Reach: the full orchestration API. Loop logic stays in C++, so future llama.cpp refactors that preserve the C API just work.

What we own:
- `bindgen` wrapper over `common/speculative.h` (~200 LoC generated + 100 LoC of safe Rust on top).
- Build-script work to compile `common/speculative.cpp` (and its dependencies — `common/sampling.cpp`, `common/log.cpp`, parts of `common/common.cpp`) into a static library and link it.

Total surface: 200–300 LoC of binding code, no `unsafe` loop logic of our own.

The catch: `common_*` symbols are part of llama.cpp's *example/helper* library, not its public API. Upstream considers them internal and reserves the right to break them. We'd be coupling to a moving target.

### 3.3 Option C — Upstream `LlamaSpeculative` to `llama-cpp-2`

The research confirms upstream `utilityai/llama-cpp-rs` has nothing in flight for speculative. A PR that wraps `common_speculative_*` under a `LlamaSpeculative` type lands the same binding work as Option B, but in the canonical crate. We then depend on whatever version it ships in.

This is the cleanest long-term path, but it depends on upstream review/merge/release calendar — which is opaque to us.

## 4. Why this is deferred

The integration work is real: 200–600 LoC depending on path, all of it touching unsafe FFI or a fork or an upstream PR. The upside today is:

- **Catalog coverage:** 6 of our ~50 served GGUF entries have known-good drafter pairings. Speculative decoding helps those 6 specifically, by an estimated 2–3× tokens/sec for accepted-prefix-heavy workloads (chat, code completion). Other workloads (deeply branching, low-acceptance) see smaller gains and occasional net-negative. The Qwen3.6-35B-A3B benchmark already showed net-negative on consumer GPUs — drafters are not free.
- **Provider economics:** Tenzro provider revenue per inference is a function of latency × throughput. A 2× speedup on Qwen3-32B cuts a provider's cost-per-token but doesn't change the fee model. Marginal revenue impact is small until the network has high enough utilization that p99 latency becomes a constraint.
- **Competitive position:** `llama-server`, vLLM, SGLang, Ollama, and MLX all already have speculative decoding. We don't differentiate by adding it; we close a feature gap that's not currently visible because we have no production users complaining about throughput on Qwen3-32B specifically.

Against that:

- **Unsafe FFI surface area:** Option A introduces 400–600 LoC of `unsafe` Rust into a critical path. Bugs in KV-cache state save/restore corrupt model output silently — no panic, no compile error, just wrong tokens. The blast radius of a subtle bug in this code is "every speculative inference produces garbage, undetected."
- **Maintenance drag:** Whichever path we pick (A, B, or C), every llama.cpp version bump requires re-validating the speculative path. We're already at `llama-cpp-2` 0.1.143; upstream is on 0.1.146+. Adding speculative on top of a fork or a custom binding makes future upgrades harder.
- **Calendar:** Option A is 1–2 weeks of careful work. Option B is similar plus build-system surgery. Option C is unbounded — upstream review timelines we don't control.
- **The Gemma 4 reality:** the headline use case (Gemma 4 MTP) is the *least* mature of the three families we'd cover. Two of four Gemma 4 sizes have no community GGUF drafter at all. The two that do (E2B and 31B) ship Q8_0/F16 only — no Q4_K_M — so memory-constrained providers can't use them anyway. Native MTP support in llama.cpp (PR #22673) is unmerged and Gemma-4-explicitly-excluded by the maintainer.

The combination is: meaningful runtime cost, modest near-term upside, and the most-cited motivation (Gemma 4 MTP) is structurally blocked upstream. The catalog metadata is the part that's cheap and durable. The runtime integration is the part that's expensive and would benefit from waiting for upstream to mature.

## 5. Decision

**Defer runtime integration.** Catalog metadata stays — `drafter_id` is wired correctly and locked by tests. The runtime continues to ignore `drafter_id` for now; `tenzro_chat`, `tenzro_serveModel`, and the `chat_completion` MCP tool do not surface a `--speculative` flag.

Re-evaluate when **any** of these conditions hold:

1. **Upstream `llama-cpp-2` ships speculative bindings.** Option C lands without us doing the work. Track `utilityai/llama-cpp-rs` for any PR/issue containing `speculative`, `draft`, or `Spec`. (None exist as of 2026-05-06.)
2. **llama.cpp PR ggml-org/llama.cpp#22673 (native MTP) merges and adds Gemma 4 architecture support.** This unblocks the headline use case. Watch the PR thread for the Gemma 4 follow-up.
3. **Production providers report throughput as a binding constraint** on Qwen3-32B, Qwen3.6-27B, or Mistral-Small-3.x. Specifically: p99 inference latency complaints on those models, or providers asking for a way to run them faster. This is a demand signal, not a guess.
4. **A Tenzro customer pays for differentiated inference SLAs** that require sub-second time-to-first-token on 24B+ dense models. Speculative is one of the cheapest paths to that target.

Until then: the catalog metadata stays correct so that when we *do* integrate, the wiring is already done; the runtime stays simple and one-code-path; we don't carry a fork or a binding to internal C++ symbols.

## 6. If/when we do integrate

When the trigger fires, the path is:

1. **Check Option C first.** If upstream has merged or is reviewing a `LlamaSpeculative` PR, contribute review/code there rather than carrying our own.
2. **If Option C is still unavailable, prefer Option B over Option A.** Loop logic in C++ is more robust than loop logic in unsafe Rust. The cost of binding `common_*` is real but it's binding work, not algorithm work.
3. **Surface as opt-in, not default.** Provider-level flag in `tenzro_serveModel` (`speculative: true`), per-request override in `tenzro_chat` (`speculative: false` to disable). Default off until benchmarks across the four pair categories (Qwen dense, Qwen MoE, Mistral, Gemma 4) confirm net-positive on representative hardware. The MoE benchmark already known-bad — keep that pairing unwired.
4. **Vocab-compatibility check at load time, not first-token time.** `common_speculative_are_compatible` (or our reimplementation) runs once on `serve_model` and the result is cached on the loaded `ServingHandle`. A misconfigured drafter must fail-fast at load, not silently corrupt outputs at inference time.
5. **Metrics.** Per-request `draft_n` and `draft_n_accepted`, surfaced in the inference response and in the provider's reputation ledger. Acceptance rate is the only honest signal of whether speculative is paying off in production.

## 7. Open upstream tracking

- [ggml-org/llama.cpp#22673](https://github.com/ggml-org/llama.cpp/pull/22673) — native MTP support. Unmerged. Gemma 4 explicitly excluded.
- [utilityai/llama-cpp-rs] — no speculative PRs/issues at time of writing. Re-search quarterly.
- `Radamanthys11/Gemma-4-{E4B,26B-A4B}-it-assistant-GGUF` — do not exist on HF. Watch for community conversions.
- `unsloth/gemma-4-*-it-assistant-GGUF` — do not exist on HF. Watch for an unsloth-curated set with Q4_K_M.

When any of these change, this document should be revisited.
