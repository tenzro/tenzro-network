# Adding a generative-media model family

Tenzro serves generative media through one generic render path. Nothing in it
names a model family. Everything a family needs that the path cannot infer is
declared in two places:

1. **The catalog** (`crates/tenzro-model/src/catalog.rs`) — what the model is,
   what it costs, what it needs, what its licence demands. Data only.
2. **A `FamilyAdapter`** (`integrations/media_gen/tenzro_media_gen/pipelines.py`)
   — the architecture-specific behaviour: converter fixups, sampling
   trajectories, multi-stage refinement.

A family that needs no special behaviour registers no adapter and still serves.
LTX-2 needs all three hooks, and is therefore the worked example below — but it
is _a registration_, not a special case in the render path.

## Why the seam exists

The render path used to read `if entry.family == "ltx2"` in three places. That
is not generic code: it is one family's code with a hole for everything else,
and each new family widens the hole. The adapter inverts it — the render path
calls hooks, families register implementations, and adding a family touches no
shared code.

The other half of the rule is just as important: **never share one family's
values with another.** Step distillation is a general technique, but the sigma
trajectory belongs to a specific training run. Handing LTX's curve to a
distilled Flux release would not error — it would render something plausible
that is not what the checkpoint was trained to produce. So every hook resolves
per family and the base class _refuses_ rather than guessing.

## The catalog fields

Generic across all families:

| field                                  | meaning                                                                                  |
| -------------------------------------- | ---------------------------------------------------------------------------------------- |
| `family`                               | selects the adapter                                                                      |
| `pipeline_class` / `transformer_class` | diffusers classes to build                                                               |
| `kinds`                                | which `MediaGenKind`s the entry may serve — declare only what has been run               |
| `default_*`, `max_resolution`          | sampling and admission defaults                                                          |
| `min_vram_gb`, `size_bytes`            | admission; refuses on hardware too small                                                 |
| `license`, `license_tier`              | operator acknowledgement, via `--accept-license <id>`                                    |
| `gguf_repo` / `gguf_file`              | quantized transformer; the rest still comes from `hf_repo`                               |
| `config_repo`                          | a locally converted snapshot to build from, when published weights need offline renaming |
| `expert_pair`                          | splits the schedule across two experts at a noise boundary                               |
| `distilled`                            | sample on the trained trajectory, resolved by the adapter                                |
| `latent_upsampler`                     | subfolder of the snapshot holding a refiner; presence enables multi-stage                |

## The adapter hooks

```python
class FamilyAdapter:
    family: str

    def patch_converter(self, entry) -> None: ...
    def sigma_schedules(self, entry) -> tuple[list[float], list[float]]: ...
    def refine(self, loaded, params, stage1_kwargs, generator) -> Any: ...
```

- **`patch_converter`** — diffusers' single-file loader resolves an unknown
  checkpoint to the nearest fingerprint it knows and applies _that_ generation's
  key map, which is a silent shape mismatch rather than a clean failure. Patch
  the entry in `SINGLE_FILE_LOADABLE_CLASSES`, not the `single_file_utils`
  module attribute — the mapping captures the function by reference.
- **`sigma_schedules`** — returns `(stage_1, stage_2)`. Called only when the
  catalog says `distilled`. Prefer importing the values the installed pipeline
  publishes over restating them, so they cannot drift.
- **`refine`** — the multi-stage render, returning pixel frames. Called only
  when the catalog names a `latent_upsampler`.

Each has a base implementation that declines. Declining is an error only if the
catalog claimed the capability, and the message names the entry, the family and
what is missing.

## Adding a family

1. Add the `MediaGenModelEntry`. If it needs none of the hooks, you are done.
2. If the published weights need offline renaming, convert once into a snapshot
   and point `config_repo` at it. Verify by parameter count: a component that
   loads with tensors on `meta` is a failed conversion, not a lenient one.
3. Subclass `FamilyAdapter`, set `family`, implement only the hooks the model
   needs, and `register_family_adapter(YourAdapter())`.
4. Declare in `kinds` only what you have actually run. A worker advertising a
   kind it has never served gets jobs accepted and then fails them.

Worked example: [`LTX_2_3_VIDEO.md`](LTX_2_3_VIDEO.md) — offline conversion,
distilled trajectory, two-stage refiner.

## Registered families

| family                                               | adapter       | hooks used                  |
| ---------------------------------------------------- | ------------- | --------------------------- |
| `ltx2`                                               | `Ltx2Adapter` | converter, sigmas, refine   |
| `qwen-image`, `flux2`, `wan2.1`, `wan2.2`, `z-image` | —             | none needed                 |
| `minimax-h3`                                         | —             | not yet servable; see below |

**MiniMax H3** is registered in the catalog but has no adapter, because it has
not been run here. Three things gate it:

- Its Community Licence grants rights _worldwide excluding the EU, UK, South
  Korea and the USA_, and extends that exclusion to the model's **outputs**.
  For a node serving a network whose consumers it cannot locate, that is a
  structural question, not a configuration one.
- The text-to-video path is ~144 GB at bf16. Community GGUFs quantize the
  FL2VA (first-and-last-frame) bundle, not the base text-to-video transformer,
  so they do not serve that kind.

- `MiniMaxH3ModularPipeline` is a Modular Diffusers class and is **not in
  diffusers 0.39**, the version this worker pins. Modular Diffusers still
  declares itself experimental. Until the class ships in a pinned release the
  entry cannot be constructed, and modular pipelines are driven through blocks
  rather than one `pipe(**kwargs)` call, so it will need an adapter regardless.

When those are resolved it becomes a `MiniMaxH3Adapter` registration — the
render path does not change.
