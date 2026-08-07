# Serving LTX-2.3 (video)

LTX-2.3 22B distilled is the checkpoint behind the video slot of the media-gen
worker. Catalog id `ltx-2.3-22b-distilled-gguf`, `Text2Video` only, 8-step
distilled schedule, 121 frames at 24 fps by default.

It is harder to stand up than the other media-gen entries for one reason: the
published weights span two Hub repos in a key layout that the installed
`diffusers` converters predate. Everything else in this document follows from
that. Nothing here patches model code — the pipeline runs on **stock diffusers
0.39**.

Related: [`UNIFIED_MEMORY_HOSTS.md`](UNIFIED_MEMORY_HOSTS.md) for why the VRAM
budget on this class of host is a safety limit rather than a tunable.

---

## 1. The one-time offline conversion

`config_repo` on the catalog entry points at a **locally converted diffusers
snapshot**, not at a Hub repo:

```
~/.tenzro/models/ltx-2.3/diffusers/     # ~12 GB
├── model_index.json                    # _class_name: LTX2Pipeline, _diffusers_version: 0.39.0
├── transformer/  vae/  audio_vae/  connectors/  vocoder/
├── text_encoder/ tokenizer/  scheduler/
```

This snapshot is **not in the repository and not on the Hub**. It is an
artifact the operator derives once, so that a plain `from_pretrained` resolves.
If the directory is lost it must be rebuilt; there is currently no script that
does it, which is why the per-component findings below are recorded in full.

Sources:

| Piece                                       | From                                                                  |
| ------------------------------------------- | --------------------------------------------------------------------- |
| transformer, both VAEs, connectors, vocoder | `unsloth/LTX-2.3-GGUF`                                                |
| tokenizer, scheduler                        | `Lightricks/LTX-2`                                                    |
| text encoder                                | `unsloth/gemma-3-12b-it-qat-bnb-4bit` (ungated, needs `bitsandbytes`) |

`hf_repo` stays `Lightricks/LTX-2.3` for provenance; only `config_repo` points
at the converted snapshot.

### Per-component geometry

The geometry was recovered by fitting each component against its published
weights until the parameter count matched exactly. A component that loads with
tensors left on `meta` is a failed conversion, not a lazy one — check the
counts.

- **transformer** — `use_prompt_embeddings: false`. Leaving it `true` builds
  LTX-2.0's `caption_projection` and strands 8 tensors. Target **4186/4186**.
  12 `prompt_adaln_single.*` keys must be renamed to `prompt_adaln.*`; the
  shipped converter misses them because its handler matches the `adaln_single`
  substring but only rewrites two other prefixes.
- **connectors** — `per_modality_projections: true`. This is the literal
  2.0-vs-2.3 switch. Head counts must make `inner_dim` match the projected
  widths (video 32×128, audio 16×128) or the zero-layer `norm_out` fails.
  4 tensors, 1.156B params.
- **video VAE** — **170/170**. The decoder carries one more upsample stage than
  the shipped rename table covers, so flat `up_blocks.7` / `up_blocks.8` map to
  `up_blocks.3.upsamplers.0` / `up_blocks.3`. The base rename table's
  **ascending order is load-bearing** — reordering it silently cascades
  `down_blocks.2 → 1 → 0.downsamplers.0`.
- **audio VAE** — geometry is _identical_ to 2.0; only the latent statistics
  keys moved, which the shipped converter already handles.
- **vocoder** — 2.3 is `LTX2VocoderWithBWE` (BigVGAN plus bandwidth extension),
  not 2.0's `LTX2Vocoder`. The default config is already correct: **1227/1227**
  under a six-entry rename (`.ups.` → `.upsamplers.`, `conv_pre`/`conv_post` →
  `conv_in`/`conv_out`, `resblocks` → `resnets`, `act_post` → `act_out`,
  `downsample.lowpass.filter`). Build it on **CPU, not `meta`** —
  `resampler.filter` is a computed non-persistent buffer and stays
  unmaterialized under `meta`.

### Patching the converter

`integrations/media_gen/tenzro_media_gen/pipelines.py::_patch_ltx2_converter`
teaches the 2.0-era transformer converter the 2.3 key layout at runtime. Patch
the entry in **`SINGLE_FILE_LOADABLE_CLASSES`**, not the `single_file_utils`
attribute — the mapping captures the function by reference, so rebinding the
module attribute has no effect. The patch is idempotent via a `_ltx23` marker.

### Text encoder

Gemma-3-12B-IT (QAT, bnb-4bit) is deliberate. Its **49 hidden states × 3840**
are exactly what the connectors' `text_proj_in_factor: 49` projects.

Do **not** switch to the official Lightricks stack: 46 GB bf16 plus ~24 GB of
Gemma, and its `--offload cpu` advice buys nothing here because GB10's memory
is unified — see [`UNIFIED_MEMORY_HOSTS.md`](UNIFIED_MEMORY_HOSTS.md).

---

## 2. It is a two-stage model, and the sampler is not free

Two things about LTX-2.3 are not optional, and both fail _quietly_ — the render
succeeds, hashes correctly, settles, and simply looks unfinished.

### The distilled sigma trajectory

A distilled checkpoint is not "the same model at fewer steps". It is trained to
jump along one specific path through noise. Passing only `num_inference_steps`
lets `FlowMatchEulerDiscreteScheduler` derive its own dynamically-shifted
sigmas — a different path — and composition still lands (that is decided early)
while fine structure never resolves.

diffusers publishes the trained trajectories:

```python
DISTILLED_SIGMA_VALUES         # 8 values, stage 1
STAGE_2_DISTILLED_SIGMA_VALUES # 3 values, stage 2
```

Note the shape of the stage-1 list — five sigmas clustered at 1.0→0.975, then a
sharp drop. Nothing a generic schedule produces.

The catalog carries `distilled: bool`, and the worker resolves the values
**per family** in `_distilled_sigmas`. That indirection is deliberate: step
distillation is a general technique but the trajectory belongs to the specific
training run, so a distilled Qwen-Image release would need its own. A family
with no known schedule raises rather than borrowing LTX's.

### Stage 2 is where detail comes from

Stage 1 lays down composition and motion at the base resolution and stops at
latents. Those are upsampled 2× and handed back to the same transformer for a
short second pass. Decoding stage 1 directly gives you the draft — and no
amount of extra stage-1 steps substitutes, because the detail is not
under-sampled, it is absent at that resolution.

The upsampler is `ltx-2.3-spatial-upscaler-x2-1.1.safetensors` (996 MB) from
`Lightricks/LTX-2.3` — ungated, no token needed. `LTX2LatentUpsamplerModel` has
**no `from_single_file`**, and 2.3 ships the upscaler as a bare safetensors at
repo root rather than a diffusers subfolder, so it needs a config authored
around it the same way the VAEs did. Read off the checkpoint:

| config                                   | value        | evidence                                                                                                                                                    |
| ---------------------------------------- | ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `in_channels`                            | 128          | `initial_conv.weight` is `(1024,128,3,3,3)`; matches VAE `latent_channels`                                                                                  |
| `mid_channels`                           | 1024         | same tensor                                                                                                                                                 |
| `num_blocks_per_stage`                   | 4            | `res_blocks.0..3`, `post_upsample_res_blocks.0..3`                                                                                                          |
| `dims`                                   | 3            | 5-D conv weights                                                                                                                                            |
| `spatial_upsample` / `temporal_upsample` | true / false | x2 spatial release                                                                                                                                          |
| `use_rational_resampler`                 | **false**    | `upsampler.0.weight` is `(4096,1024,3,3)` — a `Conv2d`→`PixelShuffleND(2)`. The default `true` builds a `SpatialRationalResampler` with different key names |

That yields an exact 72/72 key match with zero tensors left on `meta`. Anything
less is a wrong config, not a lenient load.

It lands at `~/.tenzro/models/ltx-2.3/diffusers/latent_upsampler/`, and the
catalog's `latent_upsampler` field names that subfolder — its presence is what
enables stage 2.

Stage 2 renders at 2× (768×512 → 1536×1024). Measured peak was ~70 GB of 121 GB
with the 21 GB pipeline resident; it is not free, and it is the reason
`--gpu-vram-gb` matters (below).

## 3. Two silent failure modes

Both of these leave a worker that looks completely healthy. Neither logs
anything. Together they account for most of the time lost bringing this up.

### `--max-frames` defaults to `None`, and `None` is not "no limit"

`MediaGenWorkerCapability.fits_output` reads `None` as **holds no video
capacity** and refuses every video job. A worker enrolled without `--max-frames`
enrolls fine, reports healthy, advertises the video model — and never claims.
The job sits `pending` forever with nothing written to any log.

Always pass `--max-frames`. 121 matches the catalog's `default_num_frames`
(~5 s at 24 fps).

### `--gpu-vram-gb` is a safety limit, not a performance knob

The worker's pipeline cache is bounded **solely** by this value.
`_evict_until_fits` runs only while `resident + needed > budget`, so a budget
larger than the machine disables the bound rather than loosening it.

This box ran `--gpu-vram-gb 100` on 121 GB and held a 14 GB image pipeline plus
a 21 GB video pipeline resident forever, because 35 never exceeded 100. It is
now **34**, which forces image and video to share one slot — which is what the
eviction was written for.

On a unified-memory host the GPU pool _is_ system RAM, so over-committing is
not a recoverable CUDA OOM: the kernel serves the allocation until the machine
runs out and the global OOM killer takes victims across every cgroup, including
the node. Size this to **one pipeline**, never to the machine.

---

## 4. Licensing

LTX-2.3 is `LicenseTier::CommercialCustom` under the LTX Open Weights terms, so
the node must be started with:

```
--accept-license ltx-open-weights
```

Without it, worker enrollment refuses the model and the video slot is simply
not servable. That is intended behaviour: the weights are freely
redistributable, but the terms attach conditions to commercial use above a
revenue threshold, and that is an operator acknowledgement the loader must not
infer.

---

## 5. Running it

The node and the worker are **systemd user units**, not hand-started processes:

| Unit                       | File                                              |
| -------------------------- | ------------------------------------------------- |
| `tenzro-node.service`      | `~/.config/systemd/user/tenzro-node.service`      |
| `tenzro-media-gen.service` | `~/.config/systemd/user/tenzro-media-gen.service` |

```bash
systemctl --user restart tenzro-media-gen
systemctl --user status  tenzro-media-gen
journalctl --user -u tenzro-media-gen -f
```

Two operational traps:

- **Killing the worker by hand just gets it respawned** with the old arguments
  (`Restart=always`). Change the unit, `daemon-reload`, then restart.
- **`pkill -f 'tenzro_media_gen.cli serve'` matches the shell that runs it** —
  including an agent's own shell. Use `systemctl --user stop` instead.

Enrollment is an upsert, so a restart re-announces the current capability set
rather than being refused as a duplicate.

---

## 6. Verifying

```bash
curl -s -X POST http://127.0.0.1:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tenzro_mediaGen_listWorkers","params":{}}'
```

The worker should list `ltx-2.3-22b-distilled-gguf` in `supported_models`. Then
render through `POST /v1/videos` and confirm the returned bytes hash to the
receipt's `output_hash` — that round trip is what "verified end to end" means
here, not merely that a file was produced.

---

## 7. Known issues

- **Frame counts snap to an `8k+1` grid.** A request of `seconds × fps = 48` is
  billed as 48 frames but LTX delivers 41. Ask for counts already on the grid
  (41, 49, …, 121) until billing rounds the same way the sampler does.
- **The audio branch renders but is not offered.** The joint audio+video output
  shape has no `MediaGenKind`, so only `Text2Video` is declared.
- **The image-conditioned sibling is unverified here** and deliberately not
  declared — a worker that advertises a kind it has never run gets jobs accepted
  and then fails them.
