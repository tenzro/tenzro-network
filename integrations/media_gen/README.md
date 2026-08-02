# tenzro-media-gen

**Tenzro Media Gen reference worker.** Python implementation of the diffusion
denoising loop, paired with the Rust protocol layer in
[`crates/tenzro-media-gen/`](../../crates/tenzro-media-gen).

Four kinds of job: `text2image`, `image2image`, `text2video`, `image2video`.
Two rendering shapes: a whole model on one GPU, or a **split-expert** model
where two workers each hold one half of a timestep boundary and exactly one
intermediate latent crosses the wire between them.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    tenzro-media-gen (Python)                      │
│                                                                   │
│   ┌──────────────┐   ┌────────────────┐   ┌─────────────────┐   │
│   │  pipelines   │   │     worker     │   │   commitments   │   │
│   │              │   │                │   │                 │   │
│   │ catalog row  │──▶│ claim → render │──▶│  job id digest  │   │
│   │ → diffusers  │   │ → publish      │   │  handoff sig    │   │
│   │ boundary_idx │   │ → seal         │   │  receipt sig    │   │
│   └──────────────┘   └───────┬────────┘   └─────────────────┘   │
│                              │                                   │
│                      ┌───────▼────────┐                          │
│                      │   rpc_bridge   │                          │
│                      │ JSON-RPC client│                          │
│                      └───────┬────────┘                          │
└──────────────────────────────┼──────────────────────────────────┘
                               │
                               ▼ JSON-RPC
        ┌──────────────────────────────────────────┐
        │  tenzro-node  (Rust)                     │
        │                                          │
        │  - tenzro_mediaGen_enrollWorker          │
        │  - tenzro_mediaGen_claimJob              │
        │  - tenzro_mediaGen_publishOutput         │
        │  - tenzro_mediaGen_recordHandoff         │
        │  - tenzro_mediaGen_submitReceipt         │
        └──────────────────────────────────────────┘
```

The node owns the queue, the worker registry, pricing, the payment split, and
the output store. The Python worker owns the denoising loop and nothing else:
it never decides what a job is worth, who else is working on it, or whether its
own receipt is acceptable.

## Scope

- **Models:** the node's curated generative-media catalog, read at enrollment
  via `tenzro_mediaGen_listCatalog`. Each row carries the HuggingFace repo, the
  `diffusers` pipeline class, the kinds it serves, default and maximum
  resolutions, default step count and guidance scale, frame count and fps for
  video, VRAM floor, and — for split models — the expert pair.
- **Split experts:** a row with an `expert_pair` names the two transformer
  components and the `boundary_ratio` that divides the schedule. Wan 2.2 A14B
  is the case in the catalog today: `transformer` renders the high-noise
  prefix, `transformer_2` the low-noise remainder, with the boundary at
  `0.875`. One expert needs 48 GB where the whole model needs 80, which is the
  point — two commodity cards render what one could not.
- **Distributed rendering:** the boundary is a *noise level*, not a step index.
  A step belongs to the high-noise expert while
  `t >= boundary_ratio × scheduler.config.num_train_timesteps`; timesteps
  descend, so that set is always a prefix and one integer splits the schedule.
  A 40-step job and a 100-step job therefore split at the same noise level and
  at different indices.
- **Payment:** the split follows `steps_completed` from the signed handoff.
  The high-noise worker earns `steps_completed × 10_000 / total_steps` basis
  points; the low-noise worker earns the remainder. Overstating a half would
  take a forged Ed25519 signature over the handoff preimage.
- **Commitments:** `tenzro_media_gen.commitments` recomputes the same three
  SHA-256 preimages the Rust crate does — job id, handoff, receipt — under
  three distinct domain tags, so a handoff signature cannot be replayed as a
  receipt. `tests/test_commitments.py` pins the field order and the encoding
  rules against the Rust suite's own fixtures.

## Quickstart

```bash
cd integrations/media_gen

# Requester surface only: wire types, commitment preimages, JSON-RPC client.
# No GPU stack, no torch.
pip install -e '.'

# Worker: adds torch, diffusers, transformers, accelerate, Pillow, imageio.
pip install -e '.[render]'
```

### Post a job and collect the result

```bash
tenzro-media-gen catalog

tenzro-media-gen quote \
    --kind text2image --prompt 'a fox in a plaster diorama' \
    --width 1328 --height 1328 --steps 50 --guidance-scale 4.0

JOB=$(tenzro-media-gen post \
    --kind text2image --model qwen-image \
    --requester-did did:tenzro:human:<uuid> \
    --requester-address <64-hex> \
    --max-price 5000000000000000000 \
    --prompt 'a fox in a plaster diorama' \
    --width 1328 --height 1328 --steps 50 --guidance-scale 4.0)

tenzro-media-gen get "$JOB"
tenzro-media-gen receipt "$JOB"          # includes signature_valid
tenzro-media-gen fetch "$JOB" -o fox.png
```

`post --input-image <path>` publishes the conditioning image first and binds
its hash into the job id, so an `image2image` or `image2video` job commits to
the exact bytes it was conditioned on. The worker pulls those bytes back with
`fetch --input`.

### Run a worker

```bash
tenzro-media-gen keygen                  # 32-byte Ed25519 seed + public key
export TENZRO_MEDIA_GEN_SEED=<seed_hex>

tenzro-media-gen serve \
    --worker-did did:tenzro:machine:<uuid> \
    --worker-address <64-hex> \
    --model qwen-image --model z-image-turbo \
    --max-resolution 1328 --gpu-vram-gb 48
```

`serve` enrolls, then polls for pending jobs it qualifies for and renders them
until interrupted. `enroll` does the announcement alone, for operators who
supervise the loop separately.

### Run one half of a split model

Two machines, 48 GB each, rendering `wan2.2-t2v-a14b` — a model whose VRAM
floor is 80 GB when held whole:

```bash
# machine A — holds `transformer`, renders the high-noise prefix
tenzro-media-gen serve \
    --worker-did did:tenzro:machine:<uuid-a> \
    --worker-address <64-hex-a> \
    --expert wan2.2-t2v-a14b:high_noise \
    --max-resolution 1280 --max-frames 81 --gpu-vram-gb 48

# machine B — holds `transformer_2`, finishes the low-noise remainder
tenzro-media-gen serve \
    --worker-did did:tenzro:machine:<uuid-b> \
    --worker-address <64-hex-b> \
    --expert wan2.2-t2v-a14b:low_noise \
    --max-resolution 1280 --max-frames 81 --gpu-vram-gb 48
```

Machine A claims the `high_noise` half, denoises down to the boundary,
publishes the latent, and signs a handoff naming the latent hash, its byte
length, and the step count it completed. Machine B claims the `low_noise` half,
fetches that latent, resumes the scheduler at the boundary index, decodes, and
signs the receipt. The intermediate latent is the only thing that crosses
between them.

A worker holding *both* experts claims each half separately and runs the same
two passes locally. The protocol makes no exception for it, which keeps the
signed step counts and the payment split identical either way.

Inspect either side:

```bash
tenzro-media-gen workers                 # who is enrolled, and what they hold
tenzro-media-gen get "$JOB"              # assignments, roles, share_bps, handoff
tenzro-media-gen fetch "$JOB" --latent -o latent.safetensors
```

## Module layout

| Module | Purpose |
|---|---|
| `tenzro_media_gen.types` | Python mirrors of `tenzro_types::media_gen` — params, task spec, job, handoff, receipt, worker capability — serializing to the same JSON the Rust queue expects, with the same admission checks. |
| `tenzro_media_gen.commitments` | The three SHA-256 preimages (job id, handoff, receipt) under their domain tags, plus `WorkerKey` and Ed25519 sign/verify over them via PyNaCl. Byte-identical to `crates/tenzro-media-gen/src/commitments.rs`. |
| `tenzro_media_gen.rpc_bridge` | JSON-RPC 2.0 client over `requests` covering all 18 `tenzro_mediaGen_*` methods. |
| `tenzro_media_gen.pipelines` | Catalog-row parsing, `diffusers` pipeline construction (including loading a single expert into its natural slot with the other left unset), `boundary_index` arithmetic, and the whole / high-noise / low-noise denoising loops. Heavy imports stay function-local so the base install works without torch. |
| `tenzro_media_gen.worker` | The lifecycle: enroll, poll, claim, `markRunning`, render, `publishOutput`, then `recordHandoff` or `submitReceipt`. Bounded waits on a split partner; explicit `failJob` rather than silent abandonment. |
| `tenzro_media_gen.cli` | `tenzro-media-gen catalog \| quote \| post \| jobs \| get \| cancel \| receipt \| fetch \| workers \| keygen \| enroll \| serve` |

Global flags: `--url` (node JSON-RPC endpoint, default `http://127.0.0.1:8545`),
`--timeout` (seconds per call, default 300 — raise it when publishing large
videos), `--json`, `--verbose`.

## Tests

```bash
pip install -e '.[dev]'
pytest
```

The suite needs no GPU and no torch. Catalog rows are plain dictionaries and
the boundary rule is arithmetic over a scheduler's timesteps, so a stub
scheduler pins it. `tests/conftest.py` carries the same fixture values the Rust
commitment tests use: a preimage change on either side shows up as a digest
change on one side only.

## Why split Rust + Python

The Rust crate owns the job queue, the worker registry, the pricing function,
the payment split, the commitment preimages, persistence, and the gossip wire
format — the parts that have to agree across every node and that the wider
Tenzro stack already has hardened primitives for. **No tensor library lives in
the Rust workspace.**

The Python worker owns the part that needs PyTorch: pipeline construction,
scheduler manipulation, the denoising loop, VAE decode, and video muxing.
`diffusers` carries a maintained implementation of every pipeline class in the
catalog, including the timestep-boundary dispatch that split-expert rendering
depends on. Reimplementing that in Rust would mean tracking upstream model
releases in a second language for no protocol benefit.

Same split as Tenzro Train — see `../trainer/README.md` and `../../docs/AI.md`.
