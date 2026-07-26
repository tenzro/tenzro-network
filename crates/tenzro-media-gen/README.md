# tenzro-media-gen

Protocol-only Rust crate for **Tenzro Media Gen** — diffusion image and video generation as a network resource.

## What this crate is

`tenzro-media-gen` is the **Rust protocol layer**. It owns:

- **Job queue and worker registry** (`runtime` module) — `MediaGenRuntime` holds jobs, enrolled worker capabilities, and per-job assignments. Requester paths: `post_job`, `post_split_job`, `cancel_job`. Worker paths: `enroll_worker`, `claim_job`, `mark_running`, `record_handoff`, `submit_receipt`, `fail_job`. Read paths: `get_job`, `list_jobs`, `list_jobs_by_status`, `get_receipt`, `list_workers`. Gossip-observer paths (`observe_claim` / `observe_handoff` / `observe_receipt`) apply state a peer produced without re-authorizing it as a local action. Write-through to `CF_MEDIA_GEN_RUNS` / `CF_MEDIA_GEN_RECEIPTS` / `CF_MEDIA_GEN_WORKERS`; `hydrate` restores all three on boot.
- **Pricing** (`pricing` module) — the work unit is the pixel-step: `width × height × steps × frames`, with `frames` defaulting to 1 for image kinds. `pixel_steps(kind, params)` computes it; `MediaGenPricing { per_pixel_step, base_fee }` quotes it; `enforce_ceiling` rejects a job whose posted ceiling falls below the quote at admission rather than letting a worker claim and abandon it.
- **Commitments** (`commitments` module) — three SHA-256 preimages under three distinct domain tags, so a handoff signature cannot be replayed as a receipt signature. `compute_job_id` / `expected_job_id`, `handoff_signing_bytes` / `handoff_commitment`, `receipt_signing_bytes` / `receipt_commitment`.
- **Payload store** (`output_store` module) — `MediaGenOutputStore` trait over the three payload kinds a job moves (rendered output, intermediate latent, requester-supplied conditioning image), with `compute_output_hash` and the `verify_output` / `verify_latent` / `verify_input` read-side checks. `InMemoryOutputStore` for tests; the iroh-blobs adapter lives in `tenzro-iroh`.
- **Gossip codecs** (`gossip` module) — typed encode/decode for the `tenzro/media-gen` topic (`MEDIA_GEN_TOPIC`). Five envelope variants: worker enrolled, job posted, job claimed, handoff published, receipt submitted. `decode_for_topic` refuses any other topic.
- **Protocol types** (re-exported from `tenzro_types::media_gen`) — `MediaGenTaskSpec`, `MediaGenParams`, `MediaGenKind`, `MediaGenJob`, `MediaGenStatus`, `MediaGenAssignment`, `MediaGenExpertRole`, `MediaGenExpertHolding`, `MediaGenHandoff`, `MediaGenReceipt`, `MediaGenWorkerCapability`.

## What this crate is NOT

**It does not own the denoising loop.** No tensor library lives in this crate. No Candle, no Burn, no tch-rs.

Pipeline construction, scheduler manipulation, VAE decode, and video muxing are the responsibility of the **Python reference worker** at `integrations/media_gen/`, which wraps HuggingFace `diffusers`. That worker never decides what a job is worth, who else is working on it, or whether its own receipt is acceptable — it renders and signs. The two layers communicate over the `tenzro_mediaGen_*` JSON-RPC namespace exposed by `tenzro-node`, plus the `tenzro/media-gen` gossip topic.

This is the same split as Tenzro Train. See `AI.md` §8 for the rationale.

## Scope

| Dimension | Supported |
|---|---|
| Job kinds | `text2image`, `image2image`, `text2video`, `image2video` |
| Parameters | prompt, negative prompt, width, height, steps, guidance scale, seed, frames, fps, conditioning-image hash, opaque metadata map |
| Admission bounds | 8192 px per dimension, 500 steps, 3600 frames, 8192 prompt bytes |
| Expert roles | `high_noise`, `low_noise` — a timestep-boundary expert pair, claimed independently |
| Job status | `pending`, `claimed`, `running`, `completed`, `failed`, `cancelled` |
| Pricing | `base_fee + per_pixel_step × pixel_steps`, ceiling enforced at admission |
| Payment division | whole job 10,000 bps to one worker; split job `steps_completed × 10_000 / total_steps` to the high-noise half, remainder to the low-noise half |

## Split-expert rendering

Two model shapes are called mixture-of-experts in the generative-media literature, and only one of them is a distribution primitive.

**Token-routed MoE** has a learned router selecting experts per token inside every forward pass — splitting it across machines costs a round trip per layer per token. That shape is what the language-model dispatch planner addresses; this catalog does not carry it.

**A timestep-boundary expert pair** is two transformers of identical shape trained for different noise regimes, one for the high-noise prefix of the schedule and one for the low-noise remainder. There is no learned router: a fixed noise threshold decides which expert owns a step.

```text
step belongs to the high-noise expert while
    t >= boundary_ratio × scheduler.config.num_train_timesteps
```

Timesteps descend through the schedule, so that set is always a prefix and one integer index splits it. `boundary_ratio` is a fraction of the scheduler's *training* timestep count, not of the job's step count — a 40-step job and a 100-step job split at the same noise level and at different indices, which is why the protocol records the completed step count from the signed handoff rather than assuming a fixed fraction.

Exactly one intermediate latent crosses between the two halves, once per job. One expert needs 48 GB where the whole model needs 80, so two commodity accelerators render what one could not, and the coordination cost is one blob transfer rather than one per layer. A worker with the VRAM for both halves claims each half separately anyway — the protocol makes no exception for co-location, which keeps the signed step counts and the payment division identical whether the halves run on one machine or two.

## Hashes

`MediaGenReceipt::output_hash` is the canonical Tenzro content hash — SHA-256 over the rendered bytes — and that is what the commitments bind. A transport that indexes by some other digest (iroh-blobs uses BLAKE3) owns the mapping inside its `MediaGenOutputStore` adapter and re-verifies SHA-256 at the protocol boundary, so the transport's own verification and the protocol's hash check are independent. Publishing therefore returns both: the SHA-256 for the commitment, the BLAKE3 locator for the fetch.

## Public API surface

```rust
pub use commitments::{
    compute_job_id, expected_job_id, handoff_commitment, handoff_signing_bytes, receipt_commitment,
    receipt_signing_bytes,
};
pub use error::{MediaGenError, Result};
pub use gossip::{
    decode_for_topic, encode_handoff_published, encode_job_claimed, encode_job_posted,
    encode_receipt_submitted, encode_worker_enrolled, MediaGenClaim, MediaGenGossipMessage,
    MEDIA_GEN_TOPIC,
};
pub use output_store::{
    compute_output_hash, verify_input, verify_latent, verify_output, InMemoryOutputStore,
    MediaGenOutputStore,
};
pub use pricing::{
    enforce_ceiling, pixel_steps, MediaGenPricing, DEFAULT_BASE_FEE, DEFAULT_PER_PIXEL_STEP,
};
pub use runtime::{HydratedCounts, MediaGenRuntime};

pub use tenzro_types::media_gen::{
    MediaGenAssignment, MediaGenExpertHolding, MediaGenExpertRole, MediaGenHandoff, MediaGenJob,
    MediaGenKind, MediaGenParams, MediaGenReceipt, MediaGenStatus, MediaGenTaskSpec,
    MediaGenWorkerCapability, MAX_MEDIA_GEN_DIMENSION, MAX_MEDIA_GEN_FRAMES,
    MAX_MEDIA_GEN_PROMPT_BYTES, MAX_MEDIA_GEN_STEPS,
};
```

## Integration points

- **`tenzro-types::media_gen`** — type definitions (no logic). Lives in `tenzro-types` so RPC, storage, network, CLI, the SDKs, and the Python reference worker can talk about media-gen jobs without circular dependencies.
- **`tenzro-model`** — the model catalog. `MediaGenModelEntry` names the HuggingFace repo, the `diffusers` pipeline class, the kinds it serves, default and maximum resolutions, default steps and guidance scale, frames and fps for video, a VRAM floor, and — for split models — the expert pair. `get_media_gen_catalog`, `get_media_gen_model_by_id`, `get_media_gen_models_for_kind`. The catalog holds `qwen-image`, `qwen-image-flash`, `qwen-image-edit`, `z-image-turbo`, `flux2-klein-4b`, `wan2.2-t2v-a14b`, `wan2.2-i2v-a14b`, and `wan2.2-ti2v-5b`; the two `a14b` entries carry an expert pair and so split. Because the node never loads media-gen weights, `license_tier` is enforced at worker enrollment: enrolling a capability that names a model whose terms the node was not started with is refused, and `custom_license_id()` gives the id `--accept-license` takes (`qwen-image-flash` is the one entry that needs it).
- **`tenzro-node`** — exposes the `tenzro_mediaGen_*` JSON-RPC namespace (18 methods, grouped as discovery: `listCatalog` / `quote` / `listWorkers`; requester: `postJob` / `listJobs` / `getJob` / `cancelJob` / `getReceipt` / `fetchOutput` / `fetchInput`; worker: `enrollWorker` / `claimJob` / `markRunning` / `failJob` / `publishOutput` / `recordHandoff` / `submitReceipt` / `fetchLatent`) and persists to RocksDB column families `CF_MEDIA_GEN_RUNS`, `CF_MEDIA_GEN_RECEIPTS`, and `CF_MEDIA_GEN_WORKERS`. The same surface is reachable through the MCP server and the A2A `media-gen` skill.
- **`tenzro-iroh`** — `MediaGenOutputStore` adapter over the shared iroh endpoint. Output, latent, and conditioning image are all addressed by `tenzro://blob/<hash>`.
- **`tenzro-cli`** — `tenzro media-gen` subcommand group (`catalog`, `quote`, `post-job`, `get-job`, `get-receipt`, `fetch-output`, `enroll-worker`, `claim-job`, `publish-output`, `record-handoff`, `submit-receipt`, `fetch-latent`, and the remaining worker and requester paths).
- **`integrations/media_gen/`** — Python reference worker.

## Tests

```bash
cargo test -p tenzro-media-gen
```

## Further reading

- [`AI.md`](../../docs/AI.md) §8 — architecture and rationale
- [Tenzro Media Gen docs](https://tenzro.com/docs/media-gen) — developer reference

## License

Apache-2.0
