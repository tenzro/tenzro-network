# Tenzro AI

**Decentralized, verifiable AI inference on Tenzro Network, and training as compute nodes sell**

---

## Abstract

Tenzro AI is the protocol surface that makes intelligence a network resource — discovered, compensated, attested, and settled in TNZO. It is how machines of every class, from small edge devices to the largest GPU servers, sell AI work to agents and apps: any open model, any size, on hardware its operators own. The same network providers serve dense single-replica inference, sharded Mixture-of-Experts serving for frontier-scale models, speculative decoding via Multi-Token Prediction, multi-modal inference across seven ONNX runtimes plus the llama.cpp language path, TEE-confidential inference, and diffusion image and video generation including split-expert rendering across two accelerators. A node can also sell training compute: an operator runs supervised low-rank adapter rounds whose results another machine of the same GPU model reproduces bit for bit (§6). Training jobs run in harnesses as paid milestones; every round is recorded on chain and can be challenged, and a trained model carries a provenance receipt over its rounds (§6).

None of these are silos. Compute providers serving an MoE expert shard are the same providers that serve a dense Qwen 3.5 27B chat completion. The TDIP identity that pays a per-token bill on inference is the same identity that funds a training task's escrow, and a training round is metered and receipted like any other compute a node sells. The protocol layer underwrites all of it with one consensus, one settlement asset, and one identity model.

This document describes the inference surface, the MoE serving primitives, MTP wiring, multi-modal coverage, the confidential-execution path and generative media, and how a node sells training rounds (§6).

### Verified on the live network

The following paths have been exercised from request through settlement against live network nodes, using the network's own registry and node machinery — no external orchestration:

- **Decentralized MoE serving.** Registry-native expert extraction turns a catalog MoE entry into per-expert and gate blobs addressed by `tenzro://blob/` URI. Independent nodes each load a subset of those experts into their own memory, so the full model is assembled across distributed memory that no single node holds. A router node runs the gating step and dispatches per-token expert batches to the holders — local when the expert is resident, over the holder's iroh QUIC endpoint otherwise — and combines the returned hidden states into a single forward pass. Cross-node expert loads, the distributed forward pass, and finite outputs were all confirmed.
- **Confidential-tier attestation on confidential-compute hardware.** The TEE attestation path was exercised on both an Intel TDX node and an AMD SEV-SNP node, reading evidence from the `/dev/tdx-guest` and `/dev/sev-guest` devices rather than a simulated device. This is the trust primitive confidential inference binds to.
- **Supporting surface.** The provider registry, `tenzro://blob/` addressing, and cross-node blob fetch over iroh were all verified in the same runs.

---

## 1. Decentralized AI infrastructure — design

The protocol layer treats AI compute as a coordinated resource. Three properties matter:

1. **Provider unity.** A single provider registration covers every modality and every role. A provider declares its capacities through one `ProviderCapacity` record (`max_concurrent_requests`, `requests_per_second`, `max_batch_size`, `mtp_enabled`, `drafter_vram_gb`, `moe_holdings`, `moe_roles`, `iroh_endpoint_id`). The inference router consults the same record regardless of whether the request is dense chat, an MoE expert batch, a forecast call, or an embedding lookup. The same `serves_ai()` role that lets a node serve a model also lets it rent out spare compute by the epoch — backed by the same stake. See [`docs/COMPUTE.md`](COMPUTE.md).
2. **One settlement substrate.** Inference settles per call, per token, or through a payment channel (an escrow the payer funds plus cumulative vouchers) — every path uses the same TDIP-bound `IdentityPaymentBinder`, the same delegation scope checks, and the same settlement split.
3. **Verifiability is co-designed with execution.** A verifiable chat response carries a hash commitment over the top-k logits of each decode step (TOPLOC-style, not a proof), and a node refuses a verifiable request it cannot commit rather than answering unverifiably. Any node holding the same weights can recompute the rows; a disputed commitment goes to a stake-weighted committee that excludes the provider. TEE attestation chains cover confidential inference. No zero-knowledge circuit proves model inference; STARK proofs cover identity and settlement statements (see `docs/architecture/zk-proof-systems.md`).

The crates that implement this:

- `tenzro-model` — catalog, registry, inference router, provider manager, MoE shard view, MoE dispatch planner, ONNX runtimes (forecast / vision / text-embed / segmentation / detection / audio / video)
- `crates/tenzro-model/hosts/` — the node's confined runtime-host programs (media families other than FLUX.2 klein, speech)

### Hybrid jobs: edge orchestration and model ladders

Most AI is used through model ladders: a cheap step routes, classifies, retrieves, extracts, masks old tool output, checks policy and budget or verifies an answer, and a large model is called only when the request needs one. Tenzro is designed so each rung runs on the hardware that does it best within one paid request:

| Party | Typical machine | Work | Paid for |
|---|---|---|---|
| Agent provider | Any (publishes a harness) | Authors the deterministic orchestration: plan, tools, routing, state, budget | Calls of its harness |
| Orchestration provider | An edge device (single-board computer, Jetson-class module, mini PC, gateway) | Hosts the harness, runs small local models (routing, classification, embeddings, forecasting, short outputs), fans calls out to other nodes | Hosting and local work, from the cost it saves |
| Model provider | A GPU provider | Runs the large model when the harness escalates | Inference at its price |

Each party is paid directly from the caller's signed budget, against receipts that can be replayed. The design rule is that a caller never pays more through the network than through the best direct path to the same model, so a ladder is used where many requests are easy and skipped where they are not. Edge devices orchestrate; they do not run large-model or distributed inference.

Built today:

- The light build for edge devices (`scripts/build-tier.sh edge`), which forwards every model call to a provider on the network and refuses roles that run models ([NODE.md](NODE.md#node-tiers)).
- Call-chain attribution: a settlement plan or escrow voucher may name the app, agent and tool behind a payment (`CallAttribution`), each a registered identity, covered by the payer's signature. Their creators earn the settlement's activity weight and any governed creator royalty (`fees.creator_royalty_fee_bps`) ([TOKENOMICS.md](TOKENOMICS.md#reward-calculation)).
- Payment split rules that divide one payment between several payees, each paid directly.
- Owned agent wallets: funded by their owner, never able to spend more than was funded, pausable, with expiring top-up allowances and reclaim ([SPECIFICATION.md](SPECIFICATION.md#118b-owned-funded-agents)).
- Verifiable inference commitments (section 1, item 3) and signed render receipts (section 7).


---

## 2. Inference

### 2.1 Provider model

A node runs as a model provider with `--roles ai`, registers each model it can serve through `tenzro_serveModel` (or `tenzro model serve` on the CLI), and the registration writes through to `CF_MODEL_SERVICES`. The provider's TDIP identity is bound at registration; payments route to its permissionless wallet (the node's signing key is held in its own TPM 2.0 / Secure Enclave — no custody is held).

Registration and provider announcements are authenticated over gossip. Each announcement on `tenzro/models` and `tenzro/providers` is Ed25519-signed by the node's key over a canonical preimage of its routable fields and carries the signing public key; consumers verify on ingest and drop anything unsigned or tampered. A model announcement also advertises `weights_sha256` — a streaming SHA-256 of the served on-disk weights — inside the signed payload, so a consumer can detect weight substitution before routing inference to that provider.

Provider economics:

- **Standing** is read from consensus state, never from local observations: 0 without a live serving bond, otherwise a governed bonded standing plus a governed availability standing scaled by the share of the governed window of closed hours (`routing.standing_*`, genesis 3000 + 7000 over 24 hours) in which validators' SLA verdicts found the provider available (`0..=10000`). Every node ranks a provider the same way.
- **Bonding** is optional for the Open trust tier; mandatory for the Verified and Confidential tiers. A bonded provider's stake is slashable on misbehavior (invalid receipts, repeated SLA breach, withheld results).
- **Pricing** is provider-set; the network sets no price. An operator's rate card prices units of metered work: a price per meter key (a unit such as `input_tokens`, `pixel_steps`, `characters`, `audio_out_ms`, or one registered since, optionally at a tier such as `output_tokens@priority`), quoted per a power of ten of the unit, in billionths of a dollar (settled in TNZO at the chain's rate) or in TNZO base units, with a per-call minimum. A node holds a default card and per-model cards (`tenzro_setProviderPricing`). Each card prices with one rule: each priced key costs `ceil(quantity × price / 10^per_exp)`, a key the card leaves out costs nothing, a call none of whose billable work the card prices is refused rather than served free, and the total is at least the minimum. Each model announcement carries the provider's card, so any node can price a request at any provider. An operator publishes a card for others to find and for receipts to name as a generic registry entry `<account>/card/<model>` (kind `card`) put by its own account (`tenzro provider pricing post`); `tenzro_getPriceCard`, `tenzro_listRegistry { kind }` and `tenzro_getRegistryEntry` read them. Units of metered work, service types, apps and datasets are registry entries too, registered permissionlessly behind a governed bond, so a new kind of service needs no node change. Three kinds carry chain rules from genesis: a `standard` entry's anchor is the digest of its machine-readable bundle, and a bundle digest names one standard; a `conformance` entry's anchor is an implementation's digest and its data the 32-byte bundle digests of the standing standards it passes (`registry.conformance_max_digests`); a `name` entry's id is the name (`registry.name_min_len` to `registry.name_max_len` of `[a-z0-9-]`), first come behind `registry.name_bond_tnzo`, and only governance retires it. An entry of one of these kinds keeps its kind.

**Discovery for apps that choose providers.** `tenzro_listProviders` returns every known provider with its coarse `region` (an ISO 3166-1 alpha-2 country code or one of `africa`, `asia`, `europe`, `latin-america`, `middle-east`, `north-america`, `oceania`; never anything finer, and omitted when the operator declares none, which is the right choice for a private node), its `jurisdiction`, and the live load of each model it serves (`state` cold / warming / warm / evicting, `in_flight`, `max_concurrent`, `queue_depth` of requests waiting on a warm-up, `warm_eta_ms`) with `load_as_of_ms`. A peer's load comes from its signed heartbeat, sent every few seconds on `tenzro/providers`; this node's is read when asked. `tenzro_quoteInference { model, units, verification?, provider? }` prices one request at every provider serving the model, cheapest first: the provider's announced card applied to the request's billable units (never under its minimum), plus the governed surcharge for the verification level, counting only providers that can serve at that level. The operator sets the region with `region` in the node configuration; a region finer than a country is refused at startup, and a peer's announcement carrying one is dropped.

### 2.2 Routing strategies

`InferenceRouter::route()` is modality-aware. It reads the model's modality from the registry, picks the matching runtime, and dispatches a typed `InferencePayload` (Chat / Forecast / VisionEmbed / VisionSimilarity / TextEmbed / Segment / Detect / Transcribe / VideoEmbed). The strategy is one of:

- **`LowestPrice`** — cheapest matching provider
- **`LowestLatency`** — provider with the lowest moving-window latency
- **`HighestReputation`** — highest standing among capable providers
- **`Random`** — uniformly random capable provider
- **`WeightedScore`** (default) — weighted composite of price / latency / standing

Additional filters compose with the strategy: an MTP filter when `params.custom["draft_n"]` is set, an MoE filter when expert routing is required.

### 2.3 Tail-latency hedging and failover

Once the strategy picks a primary provider, the router guards against the slow tail by hedging. It selects the next-best provider as a hedge target and starts the primary request immediately; if the primary has not answered by a short delay, the router dispatches the same request to the hedge target and returns whichever answers first, dropping the loser. Inference through the router is stateless, so a hedge is a safe duplicate — only the winning response bills the consumer and credits provider reputation.

- **Hedge delay.** Derived from the primary's observed **p95 tail latency**, clamped to `[hedge_delay_floor_ms, hedge_delay_ceiling_ms]` (defaults 40 ms / 500 ms). Each provider keeps a streaming `LatencyTail` estimator (the P² algorithm of Jain & Chlamtac — constant memory, no stored samples) so the p95 tracks live without a sliding window. A provider with no latency history hedges at the midpoint of that band. Racing at the primary's own p95 means a healthy primary has replied 19 times out of 20 by the delay, so a still-pending request is a genuine tail case — the pattern from Dean & Barroso's "The Tail at Scale", which keys hedging on the tail rather than the mean.
- **Hedge cap.** At most one hedge per request; hedges never nest.
- **Circuit-breaker respect.** A provider whose breaker is Open (quarantined after repeated failures) is never chosen as a hedge target.
- **Opt-out.** A caller that needs strict single-dispatch semantics sets `params.custom["no_hedge"] = "1"`.
- **Failover.** When both the primary and the hedge fail, the router excludes both and retries with the next-best providers up to `max_retries`, matching the existing single-dispatch failover path.
- **Fast failure detection.** Every serving node gossips a signed heartbeat on `tenzro/providers` every 2 s, signed as the machine identity its provider announcement is pinned under and verified against the key registered for it. A provider whose heartbeats stop for 3 intervals (6 s) is down, and so is one whose latest heartbeat marks it degraded. Selection, hedge-target choice and failover all skip down providers; the next clean heartbeat restores the provider at once. A heartbeat from any other key, one altered in flight, or one older than the window is dropped. Hedging covers the seconds before the window closes.

Counters are exposed over `tenzro_getRouterMetrics`: `requests` (total routed), `hedges_dispatched` (primary still pending past the delay), `hedges_won` (hedge answered before its primary), and `deadline_exceeded` (requests abandoned because the whole-request wall-clock deadline elapsed before any provider succeeded). A high `hedges_won / hedges_dispatched` ratio means hedging is rescuing tail requests; a high `hedges_dispatched / requests` ratio means primaries are routinely slow; a rising `deadline_exceeded` means providers are missing the caller's deadline outright.

### 2.3.1 Session continuity

A multi-turn `tenzro_chat` request may name a continuity session: `session: { id, continuity }` with `continuity` one of `none`, `standby` or `hot_successor`, the rich `messages` shape, and a `jurisdiction` pin (required above `none`). The serving node keeps the session's KV cache across turns, so each turn prefills only what the cache does not hold (`cached_tokens` in the response). When the session starts it also assigns a successor, by the same rule machine workloads use: a node that serves the model, whose declared jurisdiction satisfies the pin, run by another operator or at another site. The session's KV deltas are sealed to the successor's sealing key and sent over `tenzro/kv-checkpoint`, after a turn at `hot_successor` (at most once per checkpoint interval) and every 5 minutes at `standby`. The successor refuses a session built with other weights (the weights file fingerprint must match) and a delta from any node but the session's primary.

The response carries `continuity: { session_id, level, primary, successor, successor_endpoint }`. A node that routes a session records it; once the primary's heartbeats mark it down, the next request for the session is sent to the successor, which rebuilds the cache from the chain without prefill and serves the turn, then assigns a successor of its own. A successor that stops announcing is replaced and the chain restarts on the new one. Sessions idle for an hour are closed and their successor released.

**Standby replicas.** An operator who sets `[standby] enabled = true` with `models = [...]` and `fee_per_hour` has the node stage those downloaded models in host memory at startup (locked where the process may, with no engine context and no device memory) and announce them as `standby_models`. A session prefers such a node as its successor. The staged weights activate through the ordinary serve path, which skips the read from storage, on a failover (a session the node succeeds is routed to it) or a surge load. A node with a nonzero `fee_per_hour` holds a session as its successor only against a funded escrow in consensus state: the payer opens a stream escrow (`CreateEscrow` with release `Stream`) to the successor's account, with `reference` the SHA-256 of the session id, a rate of at least `fee_per_hour` per hour and an amount covering it to the escrow's expiry, and names it as `session.standby_escrow`. The successor claims the stream as it accrues and the payer may stop it at any time; no node keeps a charge book.

Every loaded language model serves sessions, batched or not. On the batch engine a checkpoint is the cache of the conversation up to the end of its last message (the generation prompt is left out, since a template renders it differently from the reply it becomes), copied out between two decode steps once it is prefilled; the successor seeds it into a slot of its own engine, and the turn it takes over prefills only what the conversation added since (the generation prompt, the previous reply and the new message). A checkpoint of a model with recurrent layers carries its whole recurrent state (about 20 MB on a small hybrid model), so checkpoints are taken at turn boundaries and no more often than `session_checkpoint_interval_secs` (default 5).

### 2.4 Chat surface

Language inference is exposed six ways over one runtime:

- `tenzro_chat` JSON-RPC (the canonical Tenzro chat shape, with `params.custom["draft_n"]` for MTP and `params.custom["chat_session"]` for the persisted session id)
- `POST /v1/chat/completions` — OpenAI-compatible HTTP endpoint (handler: `handle_openai_chat_completions`)
- `POST /v1/responses` — the Responses shape over the same handler (handler: `handle_openai_responses`, translation in `openai_responses.rs`)
- MCP `chat_completion` tool, A2A `inference` skill, CLI `tenzro chat`

Each surface is a thin wrapper over the same router and runtime — the model and provider are the same underneath.

What every surface guarantees, whichever provider serves the call:

- **Tools.** `/v1/chat/completions` accepts OpenAI `tools`, `tool_choice` and `parallel_tool_calls`, and assistant `tool_calls` / `tool` messages in the history. A call the model emits must name a declared function and carry arguments that parse and satisfy its schema, or the request fails with a named error; `tool_choice: "required"` or a named function is enforced the same way. See [`chat-api.md`](chat-api.md).
- **Signed receipts.** A locally served answer of every model type carries `tenzro_receipt`: a signature by the serving node's session key, certified by its hardware identity key (P-256, plus ML-DSA-65 where the hardware holds one) and named in the receipt, over the catalog model hash and engine, the serving machine's identity, the request nonce, the input commitment, the output hash, the billed units, the sampling parameters and the commitment hash.
- **Bounded billing.** A forwarded call is billed from the provider's signed receipt when it announced a key, and every dimension is capped by what was actually sent and received (`max_tokens`, bytes); a provider cannot over-report usage.
- **Credentials.** The caller's own Tenzro key never leaves the node that received it. A credential for the serving provider travels only when the caller supplies one as `x-tenzro-provider-access-token` with `x-tenzro-provider-dpop`. An anonymous caller cannot make a node forward at its operator's expense.
- **Prefix affinity without a side channel.** Providers announce only a count of warm prefixes. Which provider holds a caller's prefix is learned by a probe of digests salted per principal, so no one can learn from announcements or probes what another principal has asked.

### 2.5 Multi-Token Prediction

Speculative decoding lets a target model generate multiple tokens per inference step using a smaller drafter. **MTP** is the jointly-trained variant — an auxiliary head that shares hidden state with the target and produces tokens consistent with the target's distribution.

Tenzro wires MTP through the full path:

- **Catalog metadata.** Each `HfModelEntry` declares its paired drafter (`drafter_id`), the speculation flavour (`mtp_kind: DraftMtp` for joint MTP heads, `Generic` for classical drafter pairing), and the recommended starting `draft_n`.
- **Provider capacity.** `ProviderCapacity.mtp_enabled` advertises drafter co-load. `ProviderCapacity.drafter_vram_gb` advertises the VRAM headroom reserved for the drafter.
- **Router filter.** When the request carries `params.custom["draft_n"]`, the router filters to MTP-capable providers; when no MTP-capable provider exists for the model, the router falls back to standard autoregressive providers so the caller can degrade.
- **Runtime.** The MTP variant of llama.cpp consumes the joint head via Praecise Engine's `llama-cpp-2` `MtpSpeculative` wrapper. `generate_speculative` accepts the longest matching prefix on each step.
- **Drafter auto-load.** `tenzro_serveModel` reads the catalog entry's `drafter_id` and loads the paired drafter automatically. If the drafter GGUF is on disk it loads inline; otherwise a background download starts and the drafter attaches when it completes — the target serves non-speculatively in the meantime. The serve response carries an `mtp` field reporting the outcome: `none` (entry declares no MTP), `inline` (single-file MTP model, the draft head lives inside the target GGUF), `drafter_loaded`, `drafter_downloading`, `drafter_load_failed`, `drafter_unavailable`, or `disabled` (caller passed `"load_drafter": false`). A drafter problem never fails the serve. `tenzro_stopModel` unloads the drafter with its target, and the drafter is re-attached on node restart when the served model is restored.

Listed in the catalog with `mtp_kind: DraftMtp`: DeepSeek V3 (native MTP head), DeepSeek V4 Pro / Flash, GLM 5.2, Gemma 4 (E2B / E4B / 12B / 26B-A4B / 31B), Qwen 3.5 every size (0.8B / 2B / 4B / 9B / 27B / 35B-A3B / 122B-A10B / 397B-A17B), Qwen 3.6 27B and 35B-A3B. For dense models without a joint head, classical two-model speculative decoding (`MtpKind::Generic`) is wired through the same path.

### 2.6 Per-model serving profile

The catalog is the single source of truth for serving behavior. Each `HfModelEntry` carries a `serving: ServingProfile` (temperature, top_p, top_k, min_p, `presence_penalty`, `jinja_required`, `reasoning_default`) stamped from the model author's recommended values (Unsloth per-family guidance) by a single post-construction pass keyed on family + architecture — the per-family knowledge lives in one `ServingProfile::for_family` function rather than being duplicated across the struct literals. Clients consume the profile two ways: the `tenzro_modelMetadata` RPC returns it (alongside `drafter_id`, `mtp_kind`, MoE shape, and multimodal/`mmproj` flags) so any client can render or apply the recommended config, and the local serving sidecar stamps each on-disk GGUF's preset section with the profile's samplers, `--jinja`, speculative (`spec-type`), and MoE-offload (`n-cpu-moe`) flags. Request-level parameters override the profile; the profile is the default, not a ceiling.

### 2.6.1 Prefix reuse in the batch engine

A GGUF language model is served by the batch engine of Praecise Engine, the open-source inference engine Tenzro consumes (`praecise-runtime` `batching.rs`, a git dependency pinned by commit in the workspace `Cargo.toml`; its own `docs/prefix-reuse.md` is the engine-side reference): one context, a fixed pool of sequence slots, every running request decoded in one step. When a request finishes, its slot keeps what it computed, and the next request that shares a prefix with it starts where the two diverge instead of at zero. An agent's next turn repeats the whole conversation so far, so this is the difference between prefilling a few hundred tokens and prefilling tens of thousands.

What can be reused is decided by what the loaded model's memory can do, read from llama.cpp at load (`llama_model_is_recurrent`, `llama_model_is_hybrid`, `llama_model_n_swa`, `llama_model_has_encoder`, `llama_model_is_diffusion`, the GGUF's attention and pooling metadata), never from the model's name (`prefix_cache::MemoryTraits`):

| Memory | Examples | How a slot is taken back to a shorter prefix |
|---|---|---|
| Attention | dense models, MoE models (experts do not change the cache), sliding-window models served with a full window cache | Trim every position past the divergence. |
| Sliding window holding only the window (`BATCH_SWA_FULL=0`) | Gemma 3 | Trim while the window before the divergence is still held; otherwise restore a checkpoint of the window. |
| Recurrent state | Mamba, RWKV, and every hybrid of recurrent layers with attention (Qwen 3.5/3.8 gated delta nets, Granite 4 H, Jamba) | Restore the deepest checkpoint at or below the divergence, then trim the attention part from there. |
| Encoder-decoder | T5-style models | The context holds one encoder output; a request whose encoder input matches it (same namespace, same tokens) skips the encoder pass. Such a model decodes one request at a time. |
| Bidirectional or pooled, and diffusion decoders | embedding and reranking GGUFs, LLaDA-style models | Refused by the batch engine at load with the reason: it generates text a token at a time from a causal cache, which these do not. Embeddings are served by the embedding runtime, which keeps no prefix cache. |

**Checkpoints go where requests diverge.** A checkpoint is a copy of the part of a sequence's memory that cannot be trimmed (`llama_state_seq_get_data_ext` with `PARTIAL_ONLY`: the recurrent state, or the sliding window). The engine takes them at chat-turn starts. At load it renders a short probe conversation through the model's own chat template and reads which control token closes each turn (`<|im_end|>`, `<end_of_turn>`, `<|eot_id|>`, `[/INST]`, ...); a turn starts right after one. While prefilling, a slot's prefill stops at each chosen turn start so the checkpoint captures the state exactly there. It always keeps the last turn start (where the reply being generated begins, and where the next request re-renders that reply, with its reasoning dropped or a stop sequence trimmed) and one token before the prompt's end (an identical re-send then prefills a single token), then earlier turn starts, latest first, at least 256 tokens apart.

**Memory decides how many.** Checkpoints are host memory. At load the engine measures one checkpoint and one token of KV on the live context, reads the host's free memory from the backend device list, and gives checkpoints half of what is free past a reserve (a tenth of total, at least 2 GiB), split across slots (`prefix_cache::checkpoint_budget`), at most 32 per slot or `BATCH_PROMPT_CHECKPOINTS` (0 turns them off); `BATCH_CHECKPOINT_MEMORY` and `BATCH_UNIFIED_MEMORY` override the two readings. Where the KV cache and checkpoints draw on the same memory (CPU serving, integrated GPUs, Apple silicon, GB10-class hosts whose GPU reports the host's memory), a context too large to leave every slot its two most useful checkpoints is shrunk until it does, never below a quarter of what was asked or 8K tokens. On a discrete GPU the KV cache lives in device memory and the two do not compete.

**Media.** An image or audio attachment is part of the prompt's identity by content: the SHA-256 of its bytes becomes its bitmap id, and each of its positions an identity element derived from that hash. A later request reuses through an attachment only when it carries the same bytes in the same place, and a reuse never ends inside one. Text around media is prefilled in the ordinary batch; the media chunks a slot already holds are never re-encoded.

**Tenants.** `GenerationConfig::cache_salt` names whose prompt a request is. A slot's cache is tagged with the namespace it was filled in, and a request only matches slots of its own namespace, so another caller's resident prefix can neither be reused nor detected through time to first token. When nothing is reachable, the request takes an empty slot before anyone else's cache, then the least recently used one. A request with no salt shares one namespace with every other such request. The node's serving paths do not set the salt yet, so today every caller of a node shares one namespace.

**Reported.** `InferenceResult::cached_tokens` is the number of prompt tokens a request took from the cache instead of prefilling.

**Tested per memory kind.** `crates/tenzro-model/tests/prefix_reuse_architectures.rs` (ignored in a plain `cargo test`; the scheduled suite runs it in its `prefix-reuse` stage, fetching its models through `HfDownloader`) runs a dense, a sliding-window, a hybrid recurrent, a pure SSM (Mamba and RWKV), an MoE, two vision (attention and hybrid), an encoder-decoder (Flan-T5) and an embedding model through exact extension, a divergence at a turn boundary, an identical re-send, another namespace's identical prompt and two concurrent conversations, and checks every answer against a cold engine through the top-k commitments. On small CPU models an identical re-send prefills one token, an exact extension only the new turn, a turn-boundary divergence resumes at that turn, another namespace reuses nothing, the encoder-decoder model skips its encoder pass only for an identical input, and the embedding model is refused at load. Reuse covers the generating classes named above; an embedding model has no conversation to extend and is refused by the batch engine, and a diffusion model renders without a token prefix, so neither reuses a prefix. Per-model numbers are in the praecise-engine repository's `docs/prefix-reuse.md`.

**Streaming never waits on a client.** The scheduler thread hands each chunk to the client's channel without blocking. A chunk the channel cannot take yet is queued for that client alone and retried every step; a client more than 1 MiB behind is ended with an error, and a finished request's result is delivered once its stream has been fully taken (or after 60 s). The engine streams a request's reasoning on its own channel (`GenerationConfig::reasoning_tx`) as it is produced, on the batched, serial and speculative paths; `/v1/chat/completions` passes one, so a streaming client receives `reasoning_content` deltas before the answer's first `content` delta.

**Bounded queue and billing.** `BatchEngine::submit` refuses with `QueueFull` once one slot's worth of requests is already waiting, instead of queueing without bound. `output_tokens` excludes the close-marker tokens the engine forces when a reasoning budget runs out.

**Verifiable requests.** A request with `commitment_k` set gets its top-k logit commitment (`toploc::InferenceCommitment`) from the batch engine too, one record per generated token, speculative steps included.

### 2.7 Hardware backends

A provider can serve inference on whatever accelerator it has. llama.cpp's ggml runtime provides a backend for every major vendor; Tenzro exposes each one as a cargo feature on `tenzro-model` that forwards to the corresponding `GGML_<X>` cmake define at build time. A node compiled with a backend feature detects the device at runtime and reports it through `HardwareInfo` (`compiled_backends` + `active_backend`), logged when the llama backend initialises. The default build is CPU-only.

| Hardware                                          | Backend    | Cargo feature                               | Build-time requirement                                                  |
| ------------------------------------------------- | ---------- | ------------------------------------------- | ----------------------------------------------------------------------- |
| NVIDIA (datacenter + consumer)                    | CUDA       | `cuda`                                      | CUDA Toolkit                                                            |
| NVIDIA (older drivers / no VMM)                   | CUDA       | `cuda-no-vmm`                               | CUDA Toolkit                                                            |
| AMD (Instinct + Radeon)                           | HIP / ROCm | `rocm`                                      | ROCm + hipcc                                                            |
| Apple Silicon                                     | Metal      | auto-linked (macOS ARM64); `metal` to force | Xcode toolchain                                                         |
| Intel Arc / Battlemage / Data Center GPU Max / Xe | SYCL       | `sycl`                                      | oneAPI DPC++ (`icx`/`icpx`)                                             |
| Intel CPU / GPU / NPU                             | OpenVINO   | `openvino`                                  | OpenVINO runtime; device via `GGML_OPENVINO_DEVICE` (`CPU`/`GPU`/`NPU`) |
| NVIDIA / AMD / Intel Arc / ARM Mali / Adreno      | Vulkan     | `vulkan`                                    | Vulkan headers + loader + `glslc`                                       |
| Qualcomm Adreno / ARM Mali                        | OpenCL     | `opencl`                                    | OpenCL 3.0 headers + ICD                                                |
| Moore Threads MTT S-series                        | MUSA       | `musa`                                      | MUSA toolkit                                                            |
| Huawei Ascend 910 / 310 NPU                       | CANN       | `cann`                                      | Ascend CANN toolkit                                                     |
| Cross-vendor GPU (Dawn)                           | WebGPU     | `webgpu`                                    | Dawn                                                                    |
| IBM Z Telum                                       | zDNN       | `zdnn`                                      | zDNN library                                                            |
| CPU (BLAS-accelerated)                            | BLAS       | `blas`                                      | OpenBLAS / Intel MKL / Apple Accelerate                                 |
| CPU (fallback)                                    | —          | none                                        | —                                                                       |

#### NVFP4 is a different runtime, not another quant

NVFP4 is NVIDIA's Blackwell-native 4-bit format (RTX 50-series, B200, B300,
Grace-Blackwell unified-memory systems). Unsloth publishes NVFP4 builds alongside their GGUFs, and on
Blackwell they are materially faster — up to 2.5× on Qwen 3.6 27B — with an
FP8 KV cache that roughly doubles usable context.

They are **not loadable by llama.cpp**, and therefore not by this runtime.
That is why no NVFP4 repo appears in the model catalog: an entry the loader
cannot open is worse than no entry, because it fails at download time on the
operator's machine rather than at review time in this repo.

A node serves only what its own runtimes load; it does not front an external
serving process. The catalog stays GGUF-only until the runtime loads NVFP4.

**Build recipes.** Pass the backend feature to `tenzro-node` at build time.

**Do not set `CMAKE_CUDA_ARCHITECTURES` or `CUDAARCHS`.** ggml picks the architecture list itself
when they are undefined, covering Turing through Blackwell and appending `121a-real` on CUDA >= 12.9
— a hand-written list is narrower than the one you get for free, and setting one produces a binary
that compiles, links, reports `compiled backends: cpu`, and runs every layer on the CPU. The build
still exits 0.

The `CC=clang` / `CXX=clang++` / `CUDAHOSTCXX=g++` trio in `Dockerfile.cuda` is calibrated to the
image that file pins (CUDA 13.0 on Ubuntu 24.04). On a newer host it can break unrelated crates:
`aws-lc-sys` 0.40.0 does not build under clang 21, and a failed attempt leaves a CMake cache that
breaks the following build too. Outside that image, the system compiler is fine — CUDA compiles
under gcc.

Verify the result rather than trusting the exit code. `nm -D` reports nothing on a stripped release
binary, so it cannot tell the two apart:

```sh
strings target/release/tenzro-node | grep -c ggml_cuda   # 0 = CPU-only, non-zero = CUDA compiled in
```

```bash
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/cuda
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/rocm
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/vulkan
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/sycl
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/openvino
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/opencl
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/musa
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/cann
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/webgpu
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/zdnn
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/blas
```

SYCL additionally needs the oneAPI DPC++ compiler selected as the C/C++ compiler (`CC=icx CXX=icpx`). OpenVINO picks its device at runtime from `GGML_OPENVINO_DEVICE` (defaults to `CPU`); the node reports the selected device in `active_backend`.

**Container images.** Three Dockerfile variants cover the widest-reach backends; the base `Dockerfile` is the CPU image. The release publishes images for `cpu`, `cuda` and `vulkan` only (`scripts/release/build-image.sh`). `Dockerfile.rocm` is a source build: there is no published ROCm image or archive, so an AMD host either runs the Vulkan image or builds `Dockerfile.rocm` itself.

| Backend               | Dockerfile          | Run flags                                                                 |
| --------------------- | ------------------- | ------------------------------------------------------------------------- |
| CUDA                  | `Dockerfile.cuda`   | `--gpus all`                                                              |
| ROCm / HIP            | `Dockerfile.rocm`   | `--device /dev/kfd --device /dev/dri --group-add video`                   |
| Vulkan (cross-vendor) | `Dockerfile.vulkan` | `--device /dev/dri -v /usr/share/vulkan/icd.d:/usr/share/vulkan/icd.d:ro` |

Backends without a Dockerfile variant (SYCL, OpenVINO, OpenCL, MUSA, CANN, WebGPU, zDNN, BLAS) build from the base `Dockerfile` template with the vendor toolchain layered into the builder stage and the matching `--features tenzro-node/<x>` flag.

`Dockerfile.cuda` builds on multi-arch CUDA bases, so it covers x86_64 and arm64 NVIDIA hosts (Grace-Blackwell, Grace Hopper, Jetson Thor) from the same file with no extra flags.

The non-LLM modalities (forecast / vision / text-embed / segmentation / detection / ASR / video) run on ONNX Runtime. The `cuda` feature links the CUDA and TensorRT execution providers alongside llama.cpp's CUDA backend, so on an NVIDIA machine every modality runs on the GPU; `onnx-coreml` adds CoreML on Apple machines. A node whose ONNX Runtime cannot use the NVIDIA GPU it runs on refuses to start, and a model whose provider fails to register refuses to load instead of running on the CPU. `Dockerfile.cuda` builds a CUDA and TensorRT ONNX Runtime from source on both architectures.

On x86_64 the ONNX Runtime GPU binary comes from the prebuilt distribution the `ort` crate downloads. No such distribution exists for aarch64 — the CPU build is served in its place without an error — so `Dockerfile.cuda` compiles ONNX Runtime with the CUDA execution provider from source in a separate stage on that architecture, targeting Grace Hopper (sm_90), Jetson Thor (sm_110), and Grace-Blackwell GB10 (sm_121). That stage needs CUDA 13.0 or newer and roughly an extra hour and 60 GB of RAM; trim `ORT_CUDA_ARCHITECTURES` to the single target when building for one machine.

---

## 3. Mixture-of-Experts serving

MoE architectures activate a small subset of expert FFNs per token. Total parameter count can sit at 122B / 397B / 685B / 1T while the active path is only 3–37B — generation-time compute scales with the active path. Tenzro serves MoE in two modes that share the same provider population.

### 3.1 Full-replica mode

A provider whose hardware fits the entire model holds it and serves single-peer inference exactly like a dense model. Gemma 4 26B-A4B, Qwen 3.5 35B-A3B, Qwen 3.6 35B-A3B, Kimi K2.5, DeepSeek V3 on a single H200-class node.

### 3.2 Decentralized expert-shard mode

For models too large for any single provider, providers declare which subset of expert weights they hold via `ProviderCapacity.moe_holdings` — a list of `MoeExpertHolding { model_id, layer, expert, residency, committed_tps }`. Residency is `Warm` (memory-resident), `Cold` (on the holder's disk tier, decoded on demand), or `Evicting`. Each holder derives this residency from its own `MoeExpertRuntime` tier state (§3.6) rather than a static declaration, so the shard map reflects what is actually loaded at query time.

A dispatch planner (`plan_dispatch`) aggregates per-token top-k routing decisions into per-holder batches. Each batch carries the tokens whose top-k resolved to the same `(expert, holder)` tuple. The batch is dispatched directly over the holder's iroh QUIC endpoint when available, or the OpenAI-compatible HTTP endpoint otherwise.

Three mechanisms overlap and harden the cross-holder fan-out:

- **Q8_0 activation compression.** Batch hidden states cross the `tenzro/moe` wire as GGUF Q8_0 blocks (`ExpertExecuteRequest::compressed`) — one f16 scale plus 32 int8 values per 32-wide block, ~4× smaller than raw f32 at ~0.4% error. Compression engages only when `d_model % 32 == 0`; otherwise the request stays dense. The holder's `execute()` path is carrier-agnostic: `materialize_hidden()` yields f32 rows whether the request arrived compressed or dense.
- **Backup redispatch.** The planner records every reachable holder for an expert in warm-first order. The primary is carried inline on the batch; the remaining holders become `ExpertBatch::backups`. When a holder fails at the transport level or returns a holder-side error, the router redispatches the same token batch to the next standby before failing the batch.
- **Pipelined combine.** The router folds each holder response into a `MoeCombiner` the moment it arrives (fed from a `FuturesUnordered` stream), overlapping the gate-weighted gather with still-in-flight batches instead of blocking on the slowest holder. `MoeCombiner::finish` verifies every gate-selected `(expert, token)` contribution arrived.

The shard view (`MoeShardView`) is a derived view over the existing `ProviderManager` — the compute providers serving MoE shards are the same network providers that serve dense models. The view is built from a borrowed slice of providers and pinned to one `model_id`. Stale providers (non-`Active`) and providers with no MoE roles declared are filtered out at view construction.

### 3.3 Pipeline roles

MoE pipeline roles are typed on `ProviderCapacity.moe_roles: Vec<MoeProviderRole>`. A provider can declare more than one role; the router picks the matching role per request.

- `Replica` — holds the full model; serves single-peer inference. Default.
- `Router` — runs the gating step and fans out batched expert calls.
- `ExpertHolder` — holds one or more experts declared in `moe_holdings`.
- `PrefillDecode` — runs both prefill and decode phases co-located.
- `Prefill` — prefill phase only.
- `Decode` — decode phase only.

`Prefill` and `Decode` are declarations only. No KV or recurrent state is handed between peers yet: that needs the engine to export and import a sequence's state, so a provider declaring either role is counted but not routed to as a split.

### 3.4 Replication policy

`ReplicationPolicy` defaults:

- `min_replication: 2` — every active expert must be held by at least 2 distinct providers
- `max_replication: 8` — ceiling on hot-expert replication
- `hot_threshold_tps: 1_000` — committed TPS above which an expert is considered hot

The view exposes `under_replicated(policy)` and `hot_experts(policy)` so a scheduler or governance layer can act on under-served or over-loaded experts.

Placement follows measured demand and is pull-based (`tenzro-node` `moe_placement`). A holder meters the tokens it executes per expert — each of them carried in an execution receipt it signed — as an exponentially decayed rate (5 min half-life), and advertises that per-expert rate as the holding's `committed_tps`. An expert's target replication is the floor plus one holder per `hot_threshold_tps` of demand, capped at `max_replication`, so a hot expert gains holders and a cooled one stops attracting them. A holder with an upheld activation fraud proof (below) is recorded in the node's fault ledger: it no longer counts as a replica, its demand figures are ignored, it is never chosen to take on an expert, and dispatch planning skips it. New holders are chosen by rendezvous hash over the candidate providers (domain tag `tenzro/moe/demand-placement`, key `<model_id>/<layer>/<expert>`). Every node runs the same plan against its own membership view and acts only on the rows naming itself, so no node can make a peer allocate memory, and two nodes never race to cover the same replica slot. Membership-view skew produces mild over- or under-replication that heals as views converge. None of this depends on the MoE architecture: an expert is a `(model, layer, expert)` triple.

The `blob_uri` on each holder's declaration is what makes repair possible: it is the content-addressed `tenzro://blob/<hash>` the holder loaded the weights from, so a newly selected holder fetches the identical bytes over iroh-blobs. Experts whose holders declare no `blob_uri` — weights admitted from an inline payload — are skipped, since there is nowhere to fetch them from.

Each node runs a repair pass every 120 seconds, scoped to the models it already holds experts for, and admits at most two experts per pass so one membership hiccup cannot pull a whole model onto a single node.

### 3.5 LAN clusters

A model too large for one machine is served by splitting its layers across the machines of one operator's cluster. The pipeline runs inside the Praecise engine in process on every member; the node starts no separate serving program. Each machine loads only its contiguous range of blocks; hidden states (exact `f32`) travel to the next machine over a link both ends authenticate with the hardware key their machine DID derives from, and the session keys of each link come from an ephemeral exchange those signatures bind. The first machine holds the token embedding, drives generation and serves the model through the normal chat, completion and streaming surfaces (text only); a prompt is split into micro-batches so every machine works on a different one at once. Every machine in the pipeline must be an accepted member of the operator's cluster. A machine that fails fails the request in flight with an error naming its stage, and the next request reconnects to the same machines; the model is never served any other way. Supported architectures are those whose blocks the Praecise engine can split (Llama, Qwen2, Qwen3, Qwen3-MoE); any other is refused at load. Configuration, operation and status (`tenzro_layerPipelineStatus`, `tenzro node layer-pipeline-status`) are in [layer-pipeline.md](layer-pipeline.md).

**Cluster identity.** A cluster has a DID, `did:tenzro:cluster:{id}`, derived from the operator's human DID and the cluster name, so it needs no new trust root and no random id. Its members are an operator-signed list of machine DIDs: the operator approves the list with the passkey its DID derives from (a custody challenge with operation `set_cluster_membership` over the list's digest), and every listed machine accepts its own inclusion with its hardware key over `{cluster DID, machine DID, seq}`. A list the operator did not sign, a member without its own acceptance, or a sequence number not above the one held is refused; removing a machine is a new list with a higher sequence number. Lists travel in each member's `ClusterProfile.memberships` and every node checks them. Members find each other on the local network by multicast discovery on the iroh endpoint (no relay, DNS server or DHT), each announcing a binding its hardware key signs over its endpoint and peer id; a sighting counts only when that binding checks against the list. The head dials each member at the endpoint its binding names, and a member admits a tunnel session only from an endpoint a verified co-member's binding names. The cluster DID never signs anything: announcements, receipts, votes and cluster sessions stay signed by the individual machine. RPCs: `tenzro_deriveClusterMembership` (derive the DID and the digests to sign), `tenzro_acceptClusterMembership` (a member accepts, node administrators), `tenzro_setClusterMembership` (submit the approved list), `tenzro_clusterMembers` (verified members and the cluster's aggregated reputation record); CLI `tenzro cluster derive | accept | set | members`.

### 3.6 Expert-host execution

The dispatch planner in §3.2 decides _where_ each token batch goes; the expert-host execution runtime carries the tensors there and runs the math.

Every node embeds a `MoeExpertRuntime` (`tenzro-model::moe_exec`). An expert holder loads expert FFN weights (`ExpertFfn`, gate/up/down projections with SwiGLU activation) and gating networks (`GatingNetwork`) from safetensors payloads, keyed by `(model_id, layer, expert)`.

The gating network supports both router families in the catalog. Qwen-layout checkpoints use softmax top-k routing. DeepSeek-layout checkpoints (DeepSeek V3/V4, Kimi K2/K3) use sigmoid scoring with a per-expert selection bias: experts are _selected_ by `sigmoid(score) + bias` but _weighted_ by the raw sigmoid scores, renormalized to sum 1 and scaled by the checkpoint's routed scaling factor. The gate blob is self-describing — the presence of a `router.bias` tensor switches the sigmoid path on, and `routed_scaling_factor` / `shared_experts` ride in the blob's `__metadata__` — so a holder loads either family with the same call. When the checkpoint declares a fused shared-expert FFN, the router appends it as one extra weight-1.0 slot per token at index `num_experts`; the distributed layer treats it as a normal expert for announcement, holding, dispatch, and settlement.

The runtime holds experts in two tiers under a byte budget, so a holder can advertise more experts than fit in memory:

- **Memory tier.** A byte-bounded LRU keyed by `(model_id, layer, expert)`. Each admitted expert is charged its decoded footprint against `ResidencyConfig.memory_budget_bytes`. When the budget is exceeded the least-recently-used expert is evicted; a single oversized expert still stays servable rather than being rejected.
- **Disk tier.** On load, the raw safetensors blob is written to `<data_dir>/moe_experts/` (atomic temp-write then rename). An evicted expert drops from memory but remains indexed on disk, so it is decoded back on demand instead of being re-fetched over the network.
- **Auto budget.** With `ResidencyConfig::auto()` the budget is read from the host — 60% of Linux `MemAvailable` — falling back to 4 GiB off-Linux. Nodes set an explicit budget with `with_memory_budget(bytes)`.
- **Readahead.** Before a distributed forward dispatches, the coordinating node promotes the disk-tier experts named by the current routing decision back into memory (`readahead`), so the experts a batch is about to hit are warm when the batch arrives.

A holder can lower an expert's resident footprint by loading it block-quantized instead of dense. Each of the three projections is independently either dense f32 or GGUF k-quant: Q8_0 (block width 32), Q4_K, or Q6_K (block width 256). A quantized projection is stored as a flat `U8` safetensors tensor carrying `"<name>.quant"` (`q8_0` / `q4_k` / `q6_k`) and `"<name>.shape"` (`"rows,cols"`) in the blob's `__metadata__`; `ExpertFfn::from_safetensors` reads those back and keeps the projection in its quantized form. The SwiGLU forward dequantizes one weight row at a time into a scratch buffer, so the resident charge against the byte budget is the quantized size, not the dense size — a Q4_K expert costs ~4 bits/weight instead of 32, so roughly 8× more experts stay warm in the same budget. The GGUF `Q4_K_M` convention (`ExpertQuantPlan::q4_k_m`) keeps `gate`/`up` at Q4_K and `down` at Q6_K, since down-projection error dominates output quality. Projections whose column width is not a multiple of the kind's block width are left dense.

`resolve` serves a memory hit directly (touching its LRU position) and, on a disk hit, decodes the blob, admits it to memory, and re-runs eviction. `status` reports both tiers — per-expert `tier` (`memory` / `disk`), the coarsest projection `quant` tag when quantized, plus `memory_bytes`, `memory_budget_bytes`, `memory_experts`, and `disk_experts`.

The runtime also carries cumulative residency counters so an operator can see whether a node's memory budget matches the model it serves: `evicted_to_disk` (experts spilled to the disk tier under LRU pressure), `evicted_dropped` (experts dropped entirely because no disk tier is configured — these must be re-fetched from a peer holder before serving again), and `admissions_over_budget` (a single expert larger than the whole budget was admitted anyway, keeping it servable while resident bytes exceed the ceiling). A rising `evicted_dropped` on a node without a disk tier, or a non-zero `admissions_over_budget`, signals the budget is too small for the assigned shard and the holder is thrashing network fetches or overcommitting memory.

A distributed layer forward (`tenzro_moeForward`) runs in three steps on the coordinating node:

1. **Gate.** The local gating network routes each token's hidden state to its top-k experts (`route_batch`).
2. **Dispatch.** Routing decisions feed the §3.2 planner, which groups tokens into per-holder batches. Each batch is an `ExpertExecuteRequest` — hidden states as base64-encoded little-endian f32 rows — sent over a three-tier transport: local execution when this node holds the expert, the holder's iroh QUIC endpoint (`tenzro/moe` ALPN, methods `moe/execute` and `moe/status`) when one is advertised, or the holder's HTTP endpoint otherwise.
3. **Combine.** Per-expert outputs come back as `ExpertExecuteResponse` rows and are recombined per token, weighted by the gate probabilities (`combine_expert_outputs`).

The wire format is identical across all three tiers, so a holder can serve LAN peers, WAN peers, and its own local router with one code path.

**Failover.** Holder failures are handled inside the forward, not surfaced to the caller. Each batch first walks its planned holder set — primary, then each standby in the planner's warm-first order — retiring any holder that fails at the transport level or returns an execution error. When a batch exhausts every known holder, the coordinating node replans: the affected (expert, token) pairs are re-dispatched against a rebuilt shard view that excludes every provider that already failed, while contributions already gathered stay in the combiner. Replanning is bounded at two rounds per forward. Each holder failure records a reputation penalty against that provider and the winning holder's latency feeds its serving metrics, so repeat offenders sink in future dispatch plans.

By default the forward is fail-closed: tokens still unservable after the replan budget fail the request. Passing `allow_partial: true` instead drops the unservable (expert, token) contributions, renormalizes each affected token's surviving expert outputs by their gate weights, and reports the dropped slots in the response's `missing` field (`[{layer, expert, tokens}]`) alongside a `replans` count — the distributed analogue of serving with a reduced top-k under partial outages.

**Throughput metering.** Every expert holder meters its aggregate expert-forward throughput (tokens served per second over a rolling minute) and stamps the measurement onto each advertised holding as `committed_tps`, so the dispatch planner ranks holders by observed serving capacity rather than self-declared numbers.

**Execution receipts.** Every remote expert execution is signed. The holder computes an activation commitment over its output rows — for each token, the top-k features by absolute value (k = 8 by default), hashed under a dedicated domain tag — and signs `(model_id, layer, expert, token_indices, input_carrier_hash, commitment_hash)` with its session key, certified by its hardware identity key, which the receipt names. The input carrier hash covers the exact bytes the router sent (including the Q8_0-compressed hidden-state carrier when that leg is in use), so both sides hash identical bytes and the binding survives the lossy transport encoding. The router verifies each receipt inline before accepting a batch: it recomputes the activation commitment from the returned outputs, checks the signature, that the signing key is the key the provider announced, the provider binding, and token-set equality. A response with a missing, mismatched, or unverifiable receipt is treated exactly like a transport failure — the holder is retired for the batch, takes the reputation penalty, and the standby/replan path takes over. Local self-execution attaches no receipt and is never settled. A holder without a signing key on disk serves receiptless and is rejected by remote routers, matching the fail-closed provider-announcement policy.

**Settlement.** After a forward completes, the router settles the remote expert work per holder in the background — response latency never waits on settlement. Each holder is paid at its own advertised per-input-token price with its minimum-price floor; the network's inference commission is deducted, and the holder's reputation is credited with the net amount through the settled-success path — the only path that raises a provider's score, so reputation tracks paid, receipt-verified work rather than mere liveness. The settlement engine records an audit entry whose proof bytes are the concatenated activation-commitment hashes from that forward's signed receipts, and the usage tracker meters the per-model, per-holder token counts.

**Sampled receipt store and disputes.** Roughly one in 64 verified batches is persisted in full — the exact request carrier, the complete activation-commitment rows, and the holder's signed receipt. Sampling is keyed off the commitment hash itself, so a holder cannot predict which of its batches will be retained. Any node holding its own copy of the disputed expert can re-execute the stored request and compare its output rows against the committed sketch: per-row index overlap and relative feature delta must clear fixed thresholds. An upheld dispute is a fraud proof against the signed receipt and hits the holder with the quarantine-grade reputation penalty.

### 3.7 RPCs

Planning and topology:

- `tenzro_moeShardMap` — live shard map: per-expert holder list, replication factor, under-replicated experts, hot experts, role counts
- `tenzro_moePlanDispatch` — given a list of per-token routing decisions, returns the per-holder batch plan plus token-level assignment so the caller can reassemble per-token outputs
- `tenzro_moeReplicationPolicy` — current policy snapshot
- `tenzro_moeCatalogShape` — catalog-side MoE topology for a model: `num_experts`, `experts_per_token`, `shared_experts`, `params_per_expert_x10`
- `tenzro_modelMetadata` — full catalog metadata for a model: `serving` profile (samplers, jinja, reasoning), `multimodal` + `mmproj_filename`, `drafter_id` / `mtp_kind` / `mtp_default_draft_n`, MoE `moe` shape, and `architecture`. The read API over the catalog's single source of truth, consumed by the CLI and SDKs.

Execution:

- `tenzro_moeExpertLoad` / `tenzro_moeExpertUnload` — load or unload one expert FFN's safetensors weights for `(model_id, layer, expert)`
- `tenzro_moeGateLoad` / `tenzro_moeGateUnload` — load or unload a layer's gating network
- `tenzro_moeExpertStatus` — resident experts and gates on this node: per-expert tier (`memory` / `disk`) and footprint, plus `memory_bytes` / `memory_budget_bytes` / `memory_experts` / `disk_experts`
- `tenzro_moeRoute` — run the local gating network over a batch of hidden states, returning per-token top-k expert assignments
- `tenzro_moeExecute` — run a batch of tokens through one locally-resident expert FFN
- `tenzro_moeForward` — the full distributed layer forward: gate → plan → dispatch to holders (local / iroh / HTTP) → combine, with bounded in-flight failover around failed holders; `allow_partial: true` degrades unservable tokens to a gate-weight-renormalized partial combine reported under `missing`, and the response's `replans` counts failover rounds. Every remote batch is receipt-verified inline and settled per holder in the background
- `tenzro_moeListReceipts` — summaries of the sampled execution receipts this router has persisted: model, expert, token count, holder, commitment hash, storage key; optional `model_id` filter and `limit`
- `tenzro_moeDisputeReceipt` — re-execute a stored receipt's exact request carrier against this node's own copy of the expert and compare the output rows to the committed activation sketch; an upheld dispute applies the quarantine-grade reputation penalty to the receipt's signer

Weight preparation:

- `tenzro_moePrepareExperts` — extract per-expert (and optionally gate) safetensors blobs for a catalog MoE model directly from its original checkpoint using HTTP-Range tensor fetches (only the requested tensors cross the wire, never whole shards), publish each blob into the iroh blob store, and return a background job id. An optional `quant` param re-encodes each expert blob before publish: a preset string (`"q4_k_m"`, or a uniform `"q8_0"` / `"q4_k"` / `"q6_k"`) or a per-projection object (`{ "gate": "q4_k", "up": "q4_k", "down": "q6_k" }`, any projection omitted stays dense). Prepared quantized blobs are self-describing, so a holder loads them at their reduced footprint with no extra flags.
- `tenzro_moePrepareStatus` — progress snapshot for a prepare job: completed experts, each blob's `quant` tag when quantized, and the resulting `tenzro://blob/` URIs, which feed `tenzro_moeExpertLoad` / `tenzro_moeGateLoad` on any node

The extractor understands two checkpoint layouts, selected by the entry's architecture. The Qwen layout (`Qwen3MoeForCausalLM`) has routed experts and a softmax router on every MoE layer. The DeepSeek layout (`DeepseekV3ForCausalLM` — DeepSeek and Kimi families) shares the routed-expert tensor pattern and adds three things the extractor carries through: the router selection bias (`e_score_correction_bias`, packed into the gate blob as `router.bias`), the fused shared-expert FFN (prepared as one extra expert slot at index `num_experts`, requested like any other expert id), and dense-first-k layers — the extractor fetches the checkpoint's `config.json` at open, requires `first_k_dense_replace` / `routed_scaling_factor` / `n_shared_experts` to be present, refuses expert extraction on the dense layers with a clear error, and stamps the scaling factor and shared-expert count into the gate blob's `__metadata__` so the loading node needs no side-channel configuration.

### 3.8 Catalog coverage

Catalog entries that declare a `moe: Some(MoeShape { ... })` topology:

| Family          | Catalog id                                                         | num_experts | top-k | shared |
| --------------- | ------------------------------------------------------------------ | ----------: | ----: | -----: |
| Qwen 3          | `qwen3-30b-a3b`, `qwen3-coder-30b-a3b`                             |         128 |     8 |      0 |
| Qwen 3.5        | `qwen3.5-35b-a3b`, `qwen3.5-122b-a10b`                             |         256 |     8 |      1 |
| Qwen 3.5        | `qwen3.5-397b-a17b`                                                |         512 |    10 |      1 |
| Qwen 3.6        | `qwen3.6-35b-a3b`, `qwen3.6-35b-a3b-mtp`                           |         256 |     8 |      1 |
| Qwen3-Next      | `qwen3-coder-next`                                                 |         512 |    10 |      1 |
| Qwen-AgentWorld | `qwen-agentworld-35b-a3b`                                          |         256 |     8 |      1 |
| Gemma 4         | `gemma4-26b-a4b`, `gemma4-26b-a4b-qat`, `gemma4-26b-a4b-mtp-draft` |         128 |     4 |      1 |
| DiffusionGemma  | `diffusiongemma-26b-a4b`                                           |         128 |     4 |      1 |
| Kimi            | `kimi-k2-instruct`, `kimi-k2.5`, `kimi-k2.6`, `kimi-k2.7-code`     |         384 |     8 |      1 |
| Kimi K3         | `kimi-k3`                                                          |         896 |    16 |      2 |
| Ornith          | `ornith-1.0-35b`                                                   |         256 |     8 |      1 |
| Ornith          | `ornith-1.0-397b`                                                  |         512 |    10 |      1 |
| Laguna          | `laguna-s-2.1`                                                     |         256 |    10 |      1 |
| MiniMax         | `minimax-m2.7`                                                     |         256 |     8 |      0 |
| MiniMax         | `minimax-m3`                                                       |         128 |     4 |      1 |
| DeepSeek        | `deepseek-v3-0324`                                                 |         256 |     8 |      1 |
| DeepSeek        | `deepseek-v4-flash`                                                |         256 |     6 |      1 |
| DeepSeek        | `deepseek-v4-pro`                                                  |         384 |     6 |      1 |
| GLM             | `glm-5`, `glm-5.1`, `glm-5.2`                                      |         256 |     8 |      1 |
| Nemotron Nano   | `nemotron-nano-30b-a3b`, `nemotron-3-nano-omni-30b-a3b`            |         128 |     6 |      1 |
| Nemotron Ultra  | `nemotron-3-ultra-550b-a55b` and its 21 quantisation entries       |         512 |    22 |      1 |
| Nemotron Bolt   | `nemotron-3.5-bolt-74b-a9b` and its 13 quantisation entries        |         496 |     9 |      1 |
| Inkling         | `inkling`, `inkling-small`                                         |         256 |     6 |      2 |
| OpenAI          | `gpt-oss-120b`                                                     |         128 |     4 |      0 |

Per-expert extraction (`tenzro_moePrepareExperts`) additionally needs a safetensors checkpoint source mapped in `moe_safetensors_repo`. Currently mapped: `nemotron-3-ultra-550b-a55b` (NVIDIA Nemotron-H layout: ungated up/down experts with a squared-ReLU activation, a sigmoid router with selection bias, one shared expert, and the two layer-level Latent MoE projections served by `latent_projection_blob`), `qwen3-30b-a3b`, `deepseek-v3-0324`, `deepseek-v4-flash`, `deepseek-v4-pro`, `kimi-k2-instruct`, `kimi-k2.6`, and `kimi-k3`. The mapping is independent of `hf_repo`, so an entry can serve both paths: `kimi-k3` extracts experts from `moonshotai/Kimi-K3` while its whole-model artifact is the `UD-IQ1_S` quant in `unsloth/Kimi-K3-GGUF`. At 594GB for the smallest quant, that whole-model path is a pipeline cluster rather than a single host.

---

## 4. Multi-modal serving

The catalog covers seven ONNX runtimes plus the llama.cpp language path. All entries pass through `ModelRegistry::register_model()` which enforces the license tier from the `LicenseTier` enum:

- **`Permissive`** (Apache-2.0, MIT, BSD-2/3) — loaded by default, no friction
- **`Attribution`** (CC-BY-4.0) — loaded by default, attribution string is logged
- **`CommercialCustom`** (DINOv3, SAM, Gemma) — bespoke commercial-OK licenses; refuse without explicit per-family acceptance
- **`NonCommercial`** (CC-BY-NC, OpenRAIL-M, etc.) — refused unless explicit opt-in

| Modality                       | Catalog families                                                                                                                                           | RPC                  | RPC alias            |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------- | -------------------- |
| Forecast                       | TimesFM 2.5 200M, Chronos-2, TiRex-2, Toto 2.0                                                                                                               | `tenzro_forecast`    |                      |
| Vision embedding               | CLIP ViT-B/32 + L/14, SigLIP2 base/large/so400m, DINOv3 vits16/vitb16/vitl16, DINOv2                                                                       | `tenzro_imageEmbed`  | `tenzro_imageEmbed` |
| Text embedding                 | Qwen3-Embedding 0.6B/4B/8B, EmbeddingGemma-300M and EmbeddingGemma 2 (text encoder, 8192 tokens) Matryoshka, BGE-M3, Snowflake Arctic Embed L v2.0, ModernBERT-embed base/large (8192-context RoPE encoder), Qwen3-VL Embedding 2B (text, pictures and video) | `tenzro_textEmbed`   | `tenzro_textEmbed`       |
| Segmentation (point/box)       | SAM 2 base/large, EdgeSAM, MobileSAM                                                                                                                       | `tenzro_segment`     |                      |
| Segmentation (text-promptable) | SAM 3 / 3.1                                                                                                                                                | `tenzro_textSegment` |                      |
| Detection                      | RF-DETR n/s/m/b/l/2xl (90-class COCO), D-FINE n/s/m/l/x (80-class)                                                                                         | `tenzro_detect`      |                      |
| Audio ASR                      | Moonshine v2 tiny/base, Distil-Whisper small.en/medium.en/large-v3, Whisper-large-v3-turbo, Parakeet-TDT-0.6B-v3, Canary-1B-Flash                          | `tenzro_transcribe`  |                      |
| Video                          | Frame-pooled vision encoder over uniformly-sampled frames                                                                                                  | `tenzro_videoEmbed`  |                      |
| Speech synthesis               | Qwen3-TTS 12Hz 1.7B (GGUF backbone and audio projector) on the Praecise engine, in process; also `POST /v1/audio/speech` (WAV)                          | `tenzro_speak`       |                      |
| Realtime speech                | One spoken turn in, a spoken reply streamed out (server-sent events): transcript, reply text, audio chunks, then the speech leg's receipt                  | `POST /tenzro/realtime/turn` |              |
| Streaming transcription        | Live audio in as newline-delimited JSON chunks, partial and final transcripts out (server-sent events), each final segment billed by the second and receipted | `POST /tenzro/realtime/transcribe`, MCP `transcribe_stream`, CLI `tenzro transcribe stream` |              |
| Rerank                         | GGUF cross-encoders (classification-head rerankers; text, and pictures and video with a vision-language reranker) on the Praecise engine, in process; also `POST /tenzro/rerank` | `tenzro_rerank`      |                      |
| Decision                       | GGUF decision models (Laya) on the Praecise engine, in process: typed questions about a text answered in one forward pass; also `POST /tenzro/decide` | `tenzro_decide`      |                      |

**Decision models.** A decision model (`laya`, ConvAI Innovations, Apache-2.0) answers typed questions about a text without generating any: `tenzro_decide` takes a `state` (text, or any JSON value) and 1 to 64 `questions`, each `{ id, type, instructions, criteria }` with `type` one of `noul` (yes or no; `criteria` optionally describes `false` and `true`), `choice` (`criteria` lists up to 255 options, as `{ key, description? }` in the order the prompt gives them, or as an object of key to description, in the order given) or `score` (`criteria` is 2 to 10 level descriptions, level 0 first). `questions` may also be an object of id to question, the shape of the llama.cpp decision route, listed in the order given. The answer is one object per question, in request order: `noul` carries the probability of yes; `choice` the most probable `choice`, `probabilities` of every key and a `confidence`; `score` the expected level, `probabilities`, `confidence` and the `legend`. Each question is decoded on its own, so an answer does not depend on the other questions in the request. The prompt is written with the model's own `systemone` template (verified byte for byte against the template of the model file; a model whose template differs is refused, never rendered by guess), the head is cut to the budget the model was trained with, one score is read per option at its marker token, and the scores are calibrated with the temperatures stored in the model file (by question type and option count) and, for scores, its level biases. Billing is per question answered (`decision_questions`); the prompt tokens are the provider's cost. The prompt must fit the entry's context (512 tokens for the English model) and is refused, not truncated, when it does not. Checked against the llama.cpp server on the same weights: identical prompts (154 tokens over three questions) and the same answers to within 1e-3. The English checkpoint (`laya`, `laya-bf16`, 512-token prompts) is the Hub file the registry hashes. The multilingual checkpoint (`laya-multilingual`, mmBERT-base, 100+ languages) and the typed-decisions checkpoint (`laya-typed-decisions`, ModernBERT-large), both with 1024-token prompts, publish no GGUF in the engine's decision layout on the Hub (the community conversions use a different graph format), so the registry holds them as network files rebuilt from the upstream checkpoint at a pinned revision by `tools/gguf-export/convert.sh laya-multilingual|laya-typed <work-dir>` (the engine's own converter at a pinned commit, a toolchain lock of its own; BF16 for the multilingual model, Q8_0 for the typed-decisions model, each the smallest build that stays within 0.03 of the reference implementation's probabilities): the same SHA-256 comes out on x86-64 and on arm64, and each entry pins the file's SHA-256 and BLAKE3, the upstream revision and the recipe. The model's answers were checked against the reference implementation (`pip install laya`) on the same checkpoints.

A realtime turn runs the three legs on this node through their own surfaces (`tenzro_transcribe`, `tenzro_chat`, `tenzro_speak`), so each leg is admitted, billed and receipted on its own terms; the stream carries each leg's units and receipt. Every call in this table takes `verification` (`none`, `receipt`, `optimistic`, `tee`), `receipt_nonce` and an optional `provider` pin, and answers with `tenzro_receipt` when the node can sign one; a level the node cannot meet is refused before any work. A call for a model the node does not serve, or pinned to another provider's offer, is forwarded the way a chat completion is: the provider is picked from the announcements offering the model at the requested level, its task receipt is checked against the key its machine registered, the units the receipt binds are billed at the announced price and settled to the provider, and the answer comes back with `location: "network"` and the provider's name. An `optimistic` answer is drawn for re-execution on another provider at the governed rate; two answers agree when their committed results match field by field (timing fields aside; integers exactly, other numbers within 1%, numeric vectors within 5% by L2 norm, text by the greedy first-32-words rule; speech by the 20 ms loudness envelope its receipt commits to, over the first second), and a mismatch is filed as an inference fault refunding the caller. An optimistic request must fit half a fault's dispute (32 KiB) so validators can re-execute it. The receipt's input commitment is SHA-256 over a domain tag, the task name and the request's computational fields as canonical JSON (keys sorted, payment and verification fields left out); its output hash covers the engine's answer the same way. These tasks draw no samples, so a node holding the same weights recomputes the same answer up to its kernels' rounding. Rerank is metered in (query, document) pairs (`rerank_pairs`) and nothing else; a text or image embedding in input tokens; a forecast in points (`forecast_points`), one point being one series at one horizon step with every requested quantile included, and never as tokens; speech synthesis in characters spoken (`characters`) and audio produced (`audio_out_ms`). The card prices each.

Streaming transcription runs on the same realtime transport. The client streams the request body as it captures audio: a first line `{ model_id, sample_rate? (16000), language?, verification?, payment?, channel_voucher?, caller_address? }`, then one `{ pcm_s16le_base64 }` line per chunk of mono 16-bit samples; the body ending ends the stream. About once a second of new audio the node re-decodes the open segment and sends `partial` (`text`, `start_ms`, `end_ms`); it commits the segment at a pause of 300 ms once it holds 3 s, or at the quietest 20 ms of its second half once it reaches 15 s, and sends `final` (`seq`, `text`, `start_ms`, `end_ms`, `units`, `cost_wei`, `settlement`, `tenzro_receipt`); `done` carries the segment count, the audio length and the total cost. Each final segment is one `tenzro_transcribe` call, so it is admitted, billed per second of audio (`audio_ms`, the same unit as a whole recording) and receipted at the requested level; partials are not billed, so every second is billed once. The session runs on a node that serves the model; `tenzro_transcribe` routes a finished recording to any provider. SDKs: TS `multimodal.transcribeStream`, Rust `MultimodalClient::transcribe_stream`, Python `transcribe_stream`.

Forecast entries carry a `family` that selects the tensor adapter. Most are single-input graphs returning `[B, T]` or `[B, T, Q]` and use the generic path. **Chronos-2 is not**: it takes five tensors (`context`, `group_ids`, a **float** `attention_mask`, and a covariate pair) and returns `quantile_preds` shaped `[B, 13, 672]` — quantiles _before_ time. Read through the generic path, a quantile index becomes a timestep and the result is a plausible-looking series of the wrong numbers, so the family gets its own adapter and the loader verifies the graph's inputs before accepting it.

Two Chronos-2 details are easy to get wrong and are checked rather than assumed: the attention mask is float where every other transformer export uses int64, and the covariate tensors cannot be sent empty even with no covariates — the graph reshapes them to `[B, 42, 16]`, so a zero-length tensor fails _inside_ the model. They are passed full-width with an all-zero mask. Horizon is fixed at 672 (42 patches × 16) by the export; shorter requests truncate that single pass.

Each modality has a dedicated runtime in `tenzro-model` with model-specific preprocessing (mel-spectrogram for ASR, ImageNet / CLIP / SigLIP normalization for vision, BPE tokenization for text-embed). The runtime dispatch hides the per-family ABI differences (SAM 1 vs SAM 2 decoder, RF-DETR vs D-FINE post-processing, Parakeet RNN-T vs Canary NeMo Conformer-AED).

**Serving embeddings — local or network.** `tenzro_loadTextEmbeddingModel` with just `{ model_id }` (a catalog id) fetches the files the entry names onto the persistent models directory and registers the embedder on its engine: for an ONNX text encoder (engine `onnx-text-embedding`) the graph, its `model.onnx_data` external-data sidecar when the export has one (Qwen3-Embedding, EmbeddingGemma, BGE-M3 do; ModernBERT-embed is self-contained) and the tokenizer, as a co-located bundle; for a pooled embedder on the Praecise engine (engine `embed`) the GGUF and its projector — pooling, dimensions and instruction come from the catalog entry. Passing explicit `path` + `tokenizer_path` + `family` instead loads a self-hosted file already on disk. Once loaded, `tenzro_textEmbed` serves from the local runtime handle; when the model is not loaded on this node, the router dispatches to a remote provider serving it. The same choice a node makes for language models and blobs applies to embeddings: run it locally or use the network. CLI: `tenzro embed-text {catalog,load,unload,list,run}`.

**OpenAI-compatible endpoint.** `POST /v1/embeddings` is the HTTP shape of `tenzro_textEmbed` (one call over every input) and, for a model that is an image encoder, of `tenzro_imageEmbed` (one call per picture): the route calls the method, so the call is served here or by a provider serving the model, receipted, billed and sampled for optimistic re-execution as the JSON-RPC call is, and the answer carries the receipts as `tenzro_receipts`. It answers any encoder in the OpenAI wire shape — `input` as one input or an array, optional `dimensions` for Matryoshka truncation, response `{ object, data: [{ object, index, embedding }], model, usage }`. It sits on the same router as `/v1/chat/completions` and is HTTP 402-gated when a payment gate is configured, open otherwise. `usage.prompt_tokens` counts the tokens the encoder read (batch padding excluded).

**Pictures and video.** One input shape serves every embedder, on `tenzro_textEmbed`, `/v1/embeddings`, the CLI, MCP and the SDKs: an input is a string (text) or `{ text?, image?, video? }`, where `image` is a base64 PNG, JPEG or WebP picture and `video` is a list of base64 frames in order; the fields of one object are embedded together as one item. A vision-language embedder (`qwen3-vl-embedding-2b`) is a GGUF served in the node process on the Praecise engine, with its projector (`mmproj`) beside it, built by the same converter commit; its catalog entry (engine `embed`) carries the checkpoint pipeline's picture sizing (`vision_input`, the same fields as a vision-language reranker's). Pictures are resized within the pixel budget to multiples of the merged patch size and a video is sampled to the pipeline's frame count with per-slice timestamps; the input is laid out as the checkpoint's own pipeline lays it out (the video, then the picture, then the text, `NULL` for an empty input), written into the checkpoint's chat template with the instruction as the system turn, evaluated into a fresh sequence through the projector, which lays out the multi-axis rotary positions, and pooled at its last position, so an input's vector does not depend on the other inputs of the request. Its vectors are the checkpoint's own, unit length whatever `normalize` asks. Visual tokens are input tokens: an input is billed per token like text, at the model's embedding price. Text-only encoders refuse media with an invalid-input error; a model loaded as an image encoder (`tenzro_loadVisionModel`) takes inputs that are a picture alone.

**Reranking pictures and video.** `tenzro_rerank` (and `POST /tenzro/rerank`, the CLI, MCP and the SDKs) takes the same input shape for the query and for every document: a string or `{ text?, image?, video? }`. A vision-language reranker (`qwen3-vl-reranker-2b`) ships its projector (`mmproj`) beside the GGUF, built by the same converter commit, and its catalog entry carries the checkpoint pipeline's picture sizing (`vision_input`, the same fields as an embedder's `vision`). Each side is laid out as the checkpoint's own pipeline lays it out (the video with per-slice timestamps, then the picture, then the text, `NULL` for an empty side), pictures and frames are sized by that rule, and the pair is evaluated into a fresh sequence through the projector, so a document's score does not depend on the other documents. Billing is unchanged: per (query, document) pair, whatever the pair carries. A text reranker refuses pictures and video with an invalid-input error.

**OpenAI-compatible transcription endpoint.** `POST /v1/audio/transcriptions` is the HTTP shape of `tenzro_transcribe` (served here or by a provider, receipted and billed as the method is; `provider`, `verification` and `receipt_nonce` are accepted as form fields, and the plain-text formats carry the cost and the base64 receipt in `x-tenzro-cost-wei` / `x-tenzro-receipt`). It serves any transcriber over `multipart/form-data` in the OpenAI wire shape — a `file` part carrying the audio and a `model` part naming the catalog entry, with `language`, `temperature`, `timestamp_granularities` and `response_format` alongside. All five OpenAI response formats are served: `json`, `text`, `verbose_json` (segment list with `start` / `end` / `text`), and the `srt` / `vtt` subtitle bodies rendered from the runtime's segment time ranges. Requesting a format that renders time ranges makes the runtime emit them regardless of `timestamp_granularities`. The body ceiling on this route is 128 MiB rather than the 2 MiB that governs JSON bodies, since a limit sized for chat would reject an ordinary audio file. Word-level granularity, a non-empty `prompt`, and unknown form fields are refused by name rather than dropped. Wire details in [`chat-api.md`](chat-api.md#audio-transcriptions).

**Tenzro-namespaced endpoints for the modalities no vendor covers.** Forecasting, detection, segmentation and clip embedding have no OpenAI path to be compatible with, so they sit under `/tenzro/…` rather than occupying a vendor name the vendor may later define differently:

| Route                              | Method                           | Body                                                                                                                                        | Response                                                                             |
| ---------------------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `POST /tenzro/forecasts`        | `tenzro_forecast`                | `model`, `history` (oldest first), `horizon`, optional `quantiles` + `frequency_seconds`                                                    | `{ object: "forecast", point, quantiles, quantile_levels, generation_time_ms }`      |
| `POST /tenzro/detections`       | `tenzro_detect`                  | `model`, `image_base64`, optional `score_threshold` (default `0.25`)                                                                        | `{ object: "detection", detections, generation_time_ms }`                            |
| `POST /tenzro/segmentations`    | `tenzro_segment`, `tenzro_textSegment` | `model`, `image_base64`, exactly one of `prompts` (geometric) or `text_prompt` (open-vocabulary), optional `box_prompt` + `score_threshold` | `{ object: "segmentation", masks: [{ score, mask_base64 }], generation_time_ms }`    |
| `POST /tenzro/video/embeddings` | `tenzro_videoEmbed`              | `model`, `video_base64`, optional `normalize` + `frame_stride`                                                                              | `{ object: "video_embedding", embedding, dim, frames_consumed, generation_time_ms }` |

Three details follow from the modalities rather than from the wire shape. `prompts` and `text_prompt` are mutually exclusive because they select different runtimes holding different models under different ids — sending both is refused rather than resolved, since the route cannot pick for the caller. Masks travel base64-encoded: a 1024² mask as a JSON integer array is roughly 3 MB of text for one artifact, and no vendor standard governs the noun. Clip embedding is its own route rather than another `input` on `/v1/embeddings` because a clip returns one vector plus a frame count, and the vendor's `data[]` shape has no field to report how much of the clip was consumed. All four carry a base64 payload or a long series, so they sit on the 64 MiB media ceiling. Each route calls its method, so a model this node does not serve, or a call pinned with `provider`, is served by another provider under the same receipt, billing and `verification` rules as the JSON-RPC call; a model nobody serves is a 400 `model_not_loaded`. Wire details in [`chat-api.md`](chat-api.md#forecasts).

**Execution providers.** All ONNX runtimes share one session builder, and the providers it registers follow the detected hardware, with no per-host setting. On a machine with an NVIDIA GPU every session registers CUDA, with TensorRT ahead of it when the linked ONNX Runtime carries TensorRT and the TensorRT library is installed. At startup the node refuses to run on an NVIDIA machine when the binary was built without the `cuda` feature or its ONNX Runtime has no CUDA provider, and a provider that fails to register makes the model refuse to load with the cause; nothing silently runs on the CPU. Apple builds with `onnx-coreml` register CoreML; machines without an accelerator use the CPU provider.

**Limits.** Every ONNX session uses a bounded thread pool: intra-op and inter-op threads default to a quarter of the detected cores. Each ONNX runtime runs a bounded number of requests at once and holds a bounded queue behind them, through the node's admission layer; a request that finds both full is answered HTTP 429 with `Retry-After` (JSON-RPC error `-32005` with `retry_after_ms`). One `[onnx]` table in the node config overrides all three for every runtime:

```toml
[onnx]
threads = 8        # intra-op and inter-op threads per session
concurrency = 4    # requests each ONNX runtime runs at once
queue_depth = 16   # requests each ONNX runtime holds waiting
```

**One engine per model.** A model id is loaded by one engine at a time, the Praecise engine (GGUF) or one ONNX runtime. Loading it into a second engine is refused with an error naming the engine that holds it; unload it there first.

The CUDA container image and GPU model-serving setup are covered in [`deploy/validator-deployment.md`](../deploy/validator-deployment.md).

### 4.1 Vision-language GGUFs (mmproj)

Natively-multimodal chat models (the Gemma 4 family, Kimi K3, muse-glimmer-30B, and others such as Qwen3-VL, Ornith, Inkling and the Nemotron omni entry) run on the same llama.cpp language path as models that serve text alone, but accept image input. Two files load for these: the language GGUF plus a separate **multimodal projector** (mmproj) that encodes images into the model's embedding space. The catalog carries this on `HfModelEntry::mmproj` (`Some(MmprojSpec { filename })`); the projector lives in the model's own `hf_repo`, so only the filename is stored. Most entries declare their projector filename inline (Kimi K3's `mmproj-BF16.gguf`, muse-glimmer's `mmproj-kquant.gguf`), while the post-construction catalog pass stamps `mmproj-F16.gguf` onto every Gemma 4 language model (the tiny speculative `-mtp-draft` entries take no image input and stay `None`). The downloader fetches the projector alongside the model into `<models_dir>/<id>.mmproj.gguf`.

The runtime loads it in-process rather than shelling out to a server binary. `ModelRuntime::load_projector` runs at model load: it resolves `<id>.mmproj.gguf` (checking both the flat storage directory and the per-model directory a gguf-split set uses), initializes an `MtmdContext` against the already-loaded `LlamaModel`, and records the model id in a lock-free set that `ModelRuntime::supports_media` probes. The projector moves into the batch engine with the model: each media chunk is encoded and decoded for its one sequence on its own step (the projector may switch the context to non-causal attention, which cannot be shared with other sequences' tokens), while the text around it and every other request's decode run in the ordinary batch. When the projector is declared but absent on disk, or fails to initialize, the load logs a warning and the model serves text — `supports_media` returns false and an attachment is refused by name rather than silently dropped.

`ModelRuntime::generate_chat_multimodal` is the generation path: it renders the chat prompt, places one media marker per attachment in the last user turn when the caller sent none, encodes each image into an `MtmdBitmap`, and prefills the interleaved text-and-image chunks before sampling. Attachments bind positionally — the nth image in traversal order is the nth marker in the prompt. Four surfaces reach it: `tenzro_chat` in its rich shape (streaming and not), the OpenAI-compatible `/v1/chat/completions` `image_url` content part, the MCP `chat_completion` tool, and `tenzro chat`'s `/image <path>` REPL command. The simple `tenzro_chat` shape and the web `/chat` route carry a bare text message with no field an attachment could ride on, so both serve text regardless of the model's projector. The `mtmd` cargo feature on `tenzro-model` compiles the path in and is on by default; a build without it refuses an attachment and names the feature to rebuild with.

### 4.1a Hybrid and recurrent models, and the quantisation tiers

Nemotron-H models (Nano, Super, Ultra, Bolt) are labelled `nemotronh` and mix Mamba-2, MoE and attention layers. Only the attention layers hold a KV cache; the Mamba-2 layers hold a fixed-size recurrent state. The cluster planner's `ModelShape` reads the per-layer KV-head and feed-forward arrays from the GGUF header, counts the attention layers, and adds the recurrent state (`recurrent_state_bytes`) once, so a 1M-context request on Ultra is sized on 12 attention layers rather than all 108. A sharded set is sized by every shard present, not by the first file.

`QuantTier` names every quantisation the registry publishes: the plain GGUF types, the `UD-` dynamic builds (`UD-Q2_K_XL` through `UD-Q8_K_XL`, `UD-IQ1_S`, `UD-IQ1_M`, `UD-IQ2_XXS`, `UD-IQ3_XXS`, ...), `MXFP4_MOE` and `NVFP4`. A tier selects a file from a repository's own listing by its longest bounded token, so `IQ2_XXS` never picks a `UD-IQ2_XXS` file and `Q2_K` never picks `UD-Q2_K_XL`. Entries may carry `hardware_tiers` (single node of N GB, or a cluster of N nodes of M GB): descriptive metadata for operators, never a reason to omit a model; a model larger than any one machine loads across nodes by layer range (`assign_layers`) or expert shard (`MoeShardView`).

### 4.2 Sharded (gguf-split) downloads

The largest GGUFs (Kimi K2, Kimi K3, DeepSeek V3, GLM 5, MiniMax M3, the largest Qwen 3.5 MoE quants) are published as `gguf-split` sets where the catalog `hf_filename` points at the first shard (`...-00001-of-000NN.gguf`). The downloader detects this pattern, enumerates all `NN` shards from the self-describing suffix, and downloads them into a per-model directory (`<models_dir>/<id>/`) preserving their original filenames — llama.cpp only auto-continues a split set when every shard sits in one directory under its split name. `model_path`/`is_downloaded`/`downloaded_size`/`delete_model` all recognize the per-model-directory layout; single-file models keep the flat `<id>.gguf` form.

---

## 5. Confidential inference

Some inference paths require that the model weights, the input, or the output stay inside a hardware-attested enclave.

The model provider runs the inference inside an Intel TDX / AMD SEV-SNP / AWS Nitro Enclave / NVIDIA GPU Confidential Computing / Intel Tiber-attested enclave. The result is signed with an enclave-bound signing key whose attestation chain validates through one of the five vendors' root CAs. The signature anchors through the `TEE_VERIFY` precompile on-chain.

Three use-cases:

- **Model-weight confidentiality.** A provider serving a model under a license that prohibits weight extraction can run the inference inside the enclave so neither the request nor the inference path leaks the weights.
- **Input/output confidentiality.** An institutional caller (a bank requesting a NAV calculation, an asset manager pricing a bond) wraps the request and the response in HPKE envelopes sealed to the enclave's public key.
- **TEE-bound proofs.** The enclave proves a settlement statement and then attests over a digest of that exact proof (circuit, proof system, public inputs, proof bytes), so the vendor's attestation signature covers the proof. The relying party verifies the STARK, the binding, and the attestation with the strict verifier.

### 5.1 Private weights: attestation-bound key release

A provider can keep a model's weights private while operators it does not run serve them. The weights are encrypted under one content key and stay encrypted at rest and in transit. The provider opts the model in by registering a release policy on chain (a `KeyRelease` transaction, `Register`): the SHA-256 of the encrypted weights' manifest, the TPM measured boots it accepts, the TDX `MRTD` or SEV-SNP `MEASUREMENT` launch measurements it accepts, and whether a GPU must be attested too. A policy that measures nothing is refused.

For each release, the operator's environment makes a hybrid key in memory for that one release (X25519 and ML-KEM-768) and answers the provider's fresh challenge with evidence over one binding: the SHA-256 of the model, the challenge, the job's terms, the operator's machine identity and the release key's fingerprint.

- A quote over the binding by the attestation key the operator's machine identity was admitted with, its TPM manufacturer-certified, whose measured boot (the quote's PCR digest) the policy accepts.
- When the policy names launch measurements, a TDX quote or SEV-SNP report carrying the binding as its user data and one of those measurements.
- When the policy requires a GPU, an NVIDIA GPU's signed SPDM measurements answering the binding as their nonce, its device chain ending at a GPU root governance recognizes and its measurements matching the GPU reference values governance sets.

Evidence made for one release cannot be replayed for another operator, job or key. The provider's key-release broker checks the evidence, then records the release on chain (`Release`); consensus checks it again at the block's time against the policy and the governed GPU values, and records each binding once. Only after the chain accepts the release does the broker seal the content key to the environment's release key (`x25519-mlkem768-hkdf-sha256-aes-256-gcm`, bound to the binding), so reading it needs both key exchanges broken. The broker never stores the content key: it opens it for one release from the provider's hardware-held envelope and drops it once sealed.

Every key that leaves the provider has an on-chain release event naming the job's terms digest, the release key, the evidence digest, the measured boot, the launch measurement and the GPU. After the owner revokes the policy (`Revoke`), no further release is recorded, so no broker following the chain releases the key again. A model with no registered policy is not affected.

### 5.2 Attested confidential jobs, settled per unit

A confidential workload can run outside Tenzro, in a cloud or on-premises confidential VM, with or without a GPU in confidential mode. Tenzro checks the hardware's statement about the workload and pays for the work that statement covers.

The workload's attestation must answer the job's challenge and verify against the vendor's roots: an Intel TDX quote with its DCAP collateral, an AMD SEV-SNP report with its `[VCEK, ASK]` chain through the pinned AMD roots, or an NVIDIA GPU's signed measurements against the GPU roots and reference values governance sets. Each completed unit becomes an attested unit receipt committing to the job, the unit number, the verified launch measurement, the platform id (SNP `CHIP_ID`, TDX PPID or GPU device id), the evidence digest and the unit's output hash. The payer chains the receipts and signs a cumulative voucher bound to the chain head for every unit it verified, and the chain settles exactly the vouchered amount. Work whose attestation does not verify gets no receipt and no voucher.

The verifiers are tested against vendor-published evidence: a production TDX quote with Intel PCS collateral, a Milan SEV-SNP report with its VCEK, and an H100's signed measurements from NVIDIA's open-source verifier.

---

## 6. Training

A training job runs in a harness as a task whose rounds are milestones, each paid from an escrow. Every round is recorded on chain: the trainer machine commits one signed receipt per round (the checkpoint it started from, the shard, the hyperparameters, the step count, the checkpoint it ended at and the step-log root), signed through a session key its registered hardware identity certified and bound to the escrow that pays for the round. Anyone may challenge a committed round within its challenge window by posting the governed challenge bond; bonded validators replay steps sampled with a seed from the randomness beacon, and an upheld challenge slashes the trainer's compute bond and returns the escrow to its payer. A round whose receipt carries an accepted confidential-compute attestation gets the shorter governed TEE window. The milestone is released only after the window closes with no challenge pending and none upheld. The trained model is served once it is published to the catalog like any other model, and it carries a provenance receipt over its recorded rounds (see [Trained model provenance](#trained-model-provenance)).

Training itself is compute a node sells, like serving. An operator loads a downloaded catalog language model for training (`tenzro_loadTrainingModel`, operator only); the node trains low-rank adapters on it in its own process, on the Praecise engine over the same llama.cpp backend that serves models, on its CUDA device. A build or a machine without CUDA refuses the load: training never moves to the CPU. A model loaded for training is held by the training task alone, as every model is held by one engine.

`tenzro_trainRound` (operator only) runs one supervised round: a number of AdamW steps from fresh adapter weights (`adapter_seed`) or from the state a previous round ended at (`start`, fetched by content and checked against the root that round committed to), over prompt and completion records whose completion tokens carry the loss. Every step runs in deterministic mode: each op of each step must run on the CUDA device and be in that device's audited deterministic kernel set, or the round is refused. The round is metered in trained tokens (steps × sequences × tokens per sequence) against the node's rate card (`trained_tokens`) and answered with a signed receipt for the task `training`.

A round answers with its commitment (base weights, tokenized records, recipe, seed, kernel class, steps, starting and ending state roots, step-log head), each step's loss, the adapter's SHA-256 and the content URIs of the adapter, the ending state and the step log, and `result_digest`: SHA-256 over `tenzro/training/round/v1`, the model id, the weights' SHA-256, the records' SHA-256, the commitment and the adapter's SHA-256. The machine attests `result_digest` with its hardware identity key as a signed reading (`attestation` is a `sensor_data` evidence item whose payload digest is `result_digest`), so `tenzro_verifyEvidence` checks it against the key the machine registered. Another machine of the same kernel class (the same GPU model) that replays the round with the same inputs reaches the same `result_digest`, bit for bit. A harness pays a round's milestone when the attestations of two machines over the same digest both verify, or commits the round on chain and lets its challenge window settle it.

### Committing and settling rounds

A round can also be committed on chain against the milestone escrow that pays for it, so that it can be challenged, settled and later named in a provenance pack. The escrow pays the trainer's bonded account, names the training executor as its releaser, and expires after the round's challenge and decision windows close; the trainer machine holds a compute bond under its DID that covers the penalty and the challenger's reward.

`tenzro_commitTrainingRound { escrow_id, round, start_checkpoint, shard_commitment, hyperparameters, steps, end_checkpoint, step_root, kernel_class }` (operator only) commits a round this machine trained. The fields are those `tenzro_trainRound` answers with (`start_root`, `data_root`, `recipe_hash`, `steps`, `end_root`, `log_head`, `kernel_class`). The node builds the round's receipt with its own DID as the trainer, signs it through a session key its hardware identity certified, and sends it from its ledger account as a training proof transaction. Consensus records the round when the receipt is signed by the key registered for the trainer's DID, the escrow is funded and unclaimed by another round, and the bond holds enough; the round's challenge window opens at the block that commits it. It answers with `receipt_id` and `tx_hash`.

`tenzro_settleTrainingRound { receipt_id }` (operator only) settles a committed round once its challenge window has closed and no challenge is still being decided: the milestone escrow is released to the trainer, or, after an upheld challenge, returned to the payer. A settle sent while the window is open is refused. It answers with `receipt_id` and `tx_hash`. Only released rounds can be named in a provenance pack.

### Trained model provenance

A model a training job produced carries a receipt that says where it came from. `tenzro_trainedModelProvenance { model_id, base_sha256, output_sha256, rounds }`, called on the trainer machine by its operator, signs the receipt with the machine's hardware identity and returns it in a provenance pack:

| Field | Content |
|---|---|
| `model_id`, `base_sha256` | the catalog model the job trained from and the SHA-256 of its weights |
| `output_sha256` | the SHA-256 of the weights file the job produced |
| `trainer_did` | the trainer machine |
| `rounds` | the receipt ids of the job's committed rounds, first to last |
| `end_checkpoint` | the state the last round ended at, read from chain state |

The pack carries, under a certified state root with its proof from genesis, each round's record on chain and the trainer's identity registration. The node refuses to hand out a pack that would not verify.

`tenzro provenance model --file pack.json --chain-id <id> --genesis-hash <hex> --genesis-committee-root <hex> [--weights adapter.gguf]` checks it with nothing but the chain's genesis anchor: the trainer's signature against the key registered for its DID; every round committed on chain by that trainer, in order, each starting where the one before it ended, the last ending at the receipt's end state; every round's milestone escrow released (its challenge window closed with no upheld fault); and, with `--weights`, that the file is the one the receipt names. It reports each round's dataset commitment (the Merkle root over the batches it trained on) and whether the round ran in an attested environment (its receipt carried a confidential-compute attestation consensus accepted).

What a verified pack proves:

- the trainer machine, holding the hardware identity registered for its DID, signed that these weights are the export of the state its last round ended at, trained from these base weights;
- each round was committed against its escrow on chain, survived its challenge window, and was paid;
- the rounds form one unbroken chain of states, each trained on the batches its dataset commitment names.

What it does not prove:

- that the export of the end state is these weights: that is the trainer's signed statement, backed by its compute bond; a challenger who replays the rounds can check it;
- what the training data contained, its licence or its origin: the commitment fixes which batches were used, not what they are;
- that rounds outside the receipt did not also shape the weights, or that the job's buyer accepted the result.

### Trained model provenance

A model a training job produced carries a receipt that says where it came from. `tenzro_trainedModelProvenance { model_id, base_sha256, output_sha256, rounds }`, called on the trainer machine by its operator, signs the receipt with the machine's hardware identity and returns it in a provenance pack:

| Field | Content |
|---|---|
| `model_id`, `base_sha256` | the catalog model the job trained from and the SHA-256 of its weights |
| `output_sha256` | the SHA-256 of the weights file the job produced |
| `trainer_did` | the trainer machine |
| `rounds` | the receipt ids of the job's committed rounds, first to last |
| `end_checkpoint` | the state the last round ended at, read from chain state |

The pack carries, under a certified state root with its proof from genesis, each round's record on chain and the trainer's identity registration. The node refuses to hand out a pack that would not verify.

`tenzro provenance model --file pack.json --chain-id <id> --genesis-hash <hex> --genesis-committee-root <hex> [--weights adapter.gguf]` checks it with nothing but the chain's genesis anchor: the trainer's signature against the key registered for its DID; every round committed on chain by that trainer, in order, each starting where the one before it ended, the last ending at the receipt's end state; every round's milestone escrow released (its challenge window closed with no upheld fault); and, with `--weights`, that the file is the one the receipt names. It reports each round's dataset commitment (the Merkle root over the batches it trained on) and whether the round ran in an attested environment (its receipt carried a confidential-compute attestation consensus accepted).

What a verified pack proves:

- the trainer machine, holding the hardware identity registered for its DID, signed that these weights are the export of the state its last round ended at, trained from these base weights;
- each round was committed against its escrow on chain, survived its challenge window, and was paid;
- the rounds form one unbroken chain of states, each trained on the batches its dataset commitment names.

What it does not prove:

- that the export of the end state is these weights: that is the trainer's signed statement, backed by its compute bond; a challenger who replays the rounds can check it;
- what the training data contained, its licence or its origin: the commitment fixes which batches were used, not what they are;
- that rounds outside the receipt did not also shape the weights, or that the job's buyer accepted the result.

## 7. Generative media

Image, video, audio and 3D generation served by a node as one more model-serving modality. A node loads a media model from the catalog (`tenzro_loadMediaModel`) and renders with it in process; a caller asks for one render with `tenzro_mediaGen_render`, here or on a provider serving the model, and gets the output with a signed receipt over what was produced.

### 7.1 Renders and engines

Every media model runs on the node's native engine (the in-process Praecise diffusion engine) through one dispatch slot; a ported pipeline plugs into that slot, and the node starts no media helper process. A catalog entry whose port has not shipped stays listed with status `planned`, and every use of it (load, render) is refused with `this media model is planned: its native engine port has not shipped, so it cannot be used yet`.

A render is seeded, so another provider holding the same weights renders the same output up to its hardware's numeric drift. The answer commits, under a signed inference receipt for the task `media`, to the output's MIME type, SHA-256 and length, its perceptual fingerprint and the tolerance two renders must agree within. Anyone holding the receipt can re-render through the same method on another provider and file an inference fault when the fingerprints disagree; the fault refunds the caller from the provider's bond. The output is stored in the node's content store and returned as `output_blake3`, fetched with `tenzro_iroh_fetchBlob`.

A render is metered like every other modality: its work units (below) are priced against the node's rate card, collected from the caller, and added to the usage the epoch's reward metering reads.

The fingerprint follows the output's type: the mean luma of a 16 × 16 grid per picture (and for up to 8 frames of a clip), the RMS level of every 100 ms of sound, and for a 3D asset (`model/gltf-binary`) the share of its surface area in each cell of an 8 × 8 × 8 grid over the cube that bounds its mesh, each triangle counted in the cell holding its centroid. Another device simplifies a surface to other triangles but moves little area between cells; another shape moves much. Pictures and video are held to 5%, sound and 3D assets to 10% (the cap).

Two pipelines are not diffusion pipelines. A unified model that writes images as tokens of its language backbone (`janus-pro-1b`) runs its backbone from a GGUF on the node's llama.cpp runtime and its image head and VQ decoder on the media engine's backend, on the same device: the prompt and an unconditioned copy are decoded side by side, each of the 576 image tokens is sampled from the guided mix of their logits, and the finished 24 × 24 grid is decoded to a 384 × 384 image. A job asks for exactly that: width and height 384, one step per token (`steps` 576), no negative prompt. An image-to-3D model (`trellis2-4b`) takes one reference image of the object on a transparent background, at the width and height the job names, and no prompt; it samples a sparse structure, then shape and material latents, and exports a GLB with PBR textures from its 512³ surface, at the guidance its checkpoint sets per stage.

### 7.2 Kinds

`MediaGenKind` is spelled on the wire as `text2image`, `image2image`, `text2video`, `image2video`, `text2audio`, `image23d`, `text23d`, `action_policy` and `world_model`. The image-conditioned kinds name each input by its SHA-256 and role, and the receipt commits to them. Video kinds carry a frame count and fps; image kinds reject both. An `image23d` job is conditioned on its reference image alone: its prompt is empty, `width` and `height` are the reference image's, and `voxel_resolution` the grid it is built on; its output is a GLB.

`MediaGenParams` carries the prompt, an optional negative prompt, width, height, step count, guidance scale, optional seed, optional frame count and fps, an optional conditioning-image hash, and an opaque `metadata` map. Admission bounds: `MAX_MEDIA_GEN_DIMENSION = 8192`, `MAX_MEDIA_GEN_STEPS = 1024` (denoising steps, or image tokens for an autoregressive model), `MAX_MEDIA_GEN_FRAMES = 3600`, `MAX_MEDIA_GEN_PROMPT_BYTES = 8192`.

### 7.3 Catalog

Read through `tenzro_mediaGen_listCatalog`. Each row carries its `status` (`native` or `planned`) and names the HuggingFace repo, the pipeline class, the kinds it serves, default and maximum resolutions, default step count and guidance scale, frame count and fps for video, a VRAM floor, and — for split models — the expert pair.

An entry's `status` says whether this release runs it; `tenzro_mediaGen_listCatalog` is the current list. The table shows a selection.

| ID                 | Repo                                                    | Pipeline class              | Kinds                   | Default w×h | Steps | Guidance | Frames / fps | VRAM  | Expert pair |
| ------------------ | ------------------------------------------------------- | --------------------------- | ----------------------- | ----------- | ----- | -------- | ------------ | ----- | ----------- |
| `qwen-image`       | `Qwen/Qwen-Image`                                       | `QwenImagePipeline`         | text2image              | 1328 × 1328 | 50    | 4.0      | —            | 48 GB | —           |
| `qwen-image-gguf`  | `Qwen/Qwen-Image-2512` + `unsloth/Qwen-Image-2512-GGUF` | `QwenImagePipeline`         | text2image              | 1328 × 1328 | 50    | 4.0      | —            | 18 GB | —           |
| `qwen-image-flash` | `nvidia/Qwen-Image-Flash`                               | `QwenImagePipeline`         | text2image              | 1024 × 1024 | 4     | 1.0      | —            | 48 GB | —           |
| `qwen-image-edit`  | `Qwen/Qwen-Image-Edit-2511`                             | `QwenImageEditPlusPipeline` | image2image             | 1328 × 1328 | 40    | 4.0      | —            | 48 GB | —           |
| `z-image-turbo`    | `Tongyi-MAI/Z-Image-Turbo`                              | `ZImagePipeline`            | text2image              | 1024 × 1024 | 9     | 0.0      | —            | 16 GB | —           |
| `flux2-klein-4b`   | `black-forest-labs/FLUX.2-klein-4B`                     | `Flux2KleinPipeline`        | text2image, image2image | 1024 × 1024 | 4     | 1.0      | —            | 12 GB | —           |
| `flux-3-image-klein` | `black-forest-labs/flux-3-image-klein`              | `Flux3DistilledModularPipeline` | text2image, image2image | 1024 × 1024 | 16 | 1.0   | —            | 31 GB | —           |
| `wan2.2-t2v-a14b`  | `Wan-AI/Wan2.2-T2V-A14B-Diffusers`                      | `WanPipeline`               | text2video              | 1280 × 720  | 40    | 4.0      | 81 / 16      | 80 GB | 48 GB each  |
| `wan2.2-i2v-a14b`  | `Wan-AI/Wan2.2-I2V-A14B-Diffusers`                      | `WanImageToVideoPipeline`   | image2video             | 1280 × 720  | 40    | 3.5      | 81 / 16      | 80 GB | 48 GB each  |
| `wan2.2-ti2v-5b`   | `Wan-AI/Wan2.2-TI2V-5B-Diffusers`                       | `WanPipeline`               | text2video, image2video, world_model | 1280 × 704  | 50    | 5.0      | 121 / 24     | 48 GB | —           |
| `matrix-game-3`    | `Skywork/Matrix-Game-3.0`                               | `MatrixGame3I2VPipeline`    | world_model | 1280 × 704  | 3     | 1.0      | 57 / 24      | 32 GB | —           |
| `janus-pro-1b`     | `deepseek-community/Janus-Pro-1B` + `mradermacher/Janus-Pro-1B-GGUF` | `JanusProPipeline` | text2image | 384 × 384 | 576 | 5.0 | — | 8 GB | — |
| `trellis2-4b`      | `microsoft/TRELLIS.2-4B` + `microsoft/TRELLIS-image-large` + `facebook/dinov3-vitl16-pretrain-lvd1689m` | `Trellis2ImageTo3DPipeline` | image23d | (reference) | 12 | 7.5 | — | 16 GB | — |
| `hunyuan-image-3.0` | `tencent/HunyuanImage-3.0`                             | `HunyuanImage3Pipeline`     | text2image              | 1024 × 1024 | 50    | 5.0      | —            | 192 GB | —          |

`matrix-game-3` carries only its world transformer; its catalog entry `requires` the text encoder, tokenizer, autoencoder and scheduler parts of `wan2.2-ti2v-5b`, which a node fetches into that entry's own directory, so both models read one copy. Both world models are permissive (Apache-2.0 weights; MIT reference code for Matrix-Game). `wan2.2-ti2v-5b` runs natively; `matrix-game-3` stays planned until its native port passes its check. Wan2.2 TI2V 5B is trained around 1280 × 704: far below that (256 × 256) the reference implementation itself produces saturated color blocks, so serve it near its default size.

A required part is a top-level directory (`vae`) or a single file (`transformer/config.json`), and a component may name where it sits in the checkpoint (`at`, for a release that ships a transformer, prompt encoder or autoencoder as one file beside other parts). A pipeline that reads one directory, MiniMax-H3 for one, loads its entry's checkpoint view: the node links every own and required file at its view path into `media/<model>/checkpoint` (hard links into the fetched copies, each linked only after its SHA-256 matches its pin; anything else in that directory is removed). The GGUF and float8 MiniMax-H3 entries load that way: weights under `transformer/` or `transformer_ref/` beside the base config, the GGUF prompt encoder and the single-file autoencoders beside their base configs.

`janus-pro-1b` reads its image head, decoder and token ids from the checkpoint and its language backbone from the f16 GGUF its entry names, the two fetched into a directory each. `trellis2-4b` loads one checkpoint view: its pipeline's models at their paths, the structure decoder it names in `microsoft/TRELLIS-image-large` and the DINOv3 image encoder each at the path `pipeline.json` names them by. The DINOv3 weights are gated by their origin behind Meta's DINOv3 License, stricter than the MIT of TRELLIS.2's own, so the entry is gated by that licence: a node fetches it once its operator has accepted `dinov3`, from network providers or with the operator's own origin credential. `hunyuan-image-3.0` stays `planned`: an 80B Mixture-of-Experts backbone (about 169 GB at bf16, still about 45 GB at 4 bits) needs a large host and is not served from one consumer GPU; its licence excludes the European Union, the United Kingdom and South Korea, for weights and outputs.

FLUX 3 Image Klein is listed as four `planned` entries, every file pinned at one commit: `flux-3-image-klein` (distilled, bfloat16), `flux-3-image-klein-fp8` and `flux-3-image-klein-nvfp4` (their own transformer, the bfloat16 entry's text encoder and autoencoder as a dependency) and `flux-3-image-klein-base` (undistilled, for fine-tuning). Multi-reference edits are `image2image` jobs with several edit sources in order; bounding boxes are written into the prompt. The model takes full scene captions, and its card recommends writing them with `flux-3-image-klein-pup`, a 9B vision-language model listed in the language catalog: a caller that wants upsampling calls it and passes the caption on, the node never chains the two. The image and action weights are gated at their origin under the FLUX Kommunity License (`flux-kommunity-1.0`, `CommercialCustom`): a node fetches them with its operator's own Hugging Face credential, from an account that has accepted the terms, and serves them once the operator has accepted `flux-kommunity-1.0`; whether a use is non-commercial or within the Qualifying User grant is the operator's to judge from the licence the entry carries.

Rows with an image-conditioned kind resolve to a sibling pipeline class where the family provides one — `WanPipeline` becomes `WanImageToVideoPipeline` for an `image2video` job against `wan2.2-ti2v-5b`, while a class that already covers image input keeps it.

`qwen-image-flash` is `qwen-image` distilled onto a four-step trajectory with guidance disabled — the same 20.4B transformer and the same VRAM floor, one twelfth of the pixel-steps, so it meters at one twelfth of the work. It is the one row not under a permissive license: the NVIDIA Open Model License puts it in the `CommercialCustom` tier, and a node serves it only when started with `--accept-license nvidia-open-model`. Every other row is admitted by default. The check runs when the node loads the model (`tenzro_loadMediaModel`).

### 7.4 Precision

The native engine loads weights at bf16, the format that passed the quality check against the reference. Precision is a node runtime choice, not a catalog property: `MediaGenModelEntry` carries no precision field.

### 7.5 Split-expert rendering

Two distinct model shapes are called mixture-of-experts in the generative-media literature.

**Token-routed MoE** — a learned router selects experts per token inside every forward pass. Splitting it across machines means a round trip per layer per token. This is the shape §3 addresses for language models, where the dispatch planner amortizes it; it is not what the media catalog carries.

**Timestep-boundary expert pairs** — two transformers trained for different noise regimes, one for the high-noise prefix of the schedule and one for the low-noise remainder. There is no learned router: a fixed noise threshold decides which expert owns a step. Wan 2.2 A14B is this shape. Exactly one intermediate latent crosses between the two halves, once per job.

One expert needs 48 GB where the whole model needs 80, and only one is resident at a time.

**The boundary is a noise level, not a step index.** A step belongs to the high-noise expert while

```
t >= boundary_ratio × scheduler.config.num_train_timesteps
```

Timesteps descend through the schedule, so that set is always a prefix and one integer index splits it. `boundary_ratio` is a fraction of the scheduler's _training_ timestep count — for Wan 2.2 A14B, `0.875` of 1000. A 40-step job and a 100-step job therefore split at the same noise level and at different indices, so the split point is computed per render rather than assumed as a fixed fraction.

Split-expert models are `planned` until their pipeline is ported to the native engine.

**One render, one machine.** A split model renders on a node that holds both experts; the node refuses to render a model whose catalog entry splits it across two machines.

### 7.6 Work units

The work unit is the **pixel-step**: `width × height × steps × frames`, frames defaulting to 1 for image kinds. Audio is metered on its duration (25 frames per second times steps), 3D on its voxel grid, an action policy per action chunk of its observation canvas, and a world model on simulated seconds, denoising steps and held session time over its canvas (`tenzro_types::media_gen::pixel_steps`, `world_model_units`).

### 7.7 Surfaces

| Method | What it does |
| --- | --- |
| `tenzro_mediaGen_listCatalog` | The media catalog: each entry's status, repo, pipeline class, kinds, defaults, VRAM floor and expert pair |
| `tenzro_mediaGen_render` | One seeded render with a signed receipt, metered against the node's rate card |
| `tenzro_loadMediaModel` / `tenzro_unloadMediaModel` | Load or release a media model on this node (operator only) |

The same surface is reachable through the CLI (`tenzro media-gen catalog`, `tenzro media-gen render`), the MCP tools `media_gen_list_catalog` and `media_gen_render`, and the SDKs. Job queues, worker pools, quotes and the OpenAI-compatible image and video routes are applications built over these methods.
