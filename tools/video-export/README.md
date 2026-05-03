# Tenzro Video Encoder ONNX Export Harness

Reproducible exporter that takes upstream video encoder foundation
models (V-JEPA 2 / 2.1, VideoMAE, …) and produces single-file ONNX
artifacts compatible with the Tenzro `VideoRuntime`
(`crates/tenzro-model/src/video_runtime.rs`).

## Why this exists

As of 2026-04, the OSS landscape has **no** permissive +
ONNX-shippable encoder-only video model. VideoMAE v1/v2 are
CC-BY-NC-4.0 (non-commercial); V-JEPA 2 / 2.1 license is unclear on
the model card and ONNX export is non-trivial (custom 3D-conv stem).
This harness exists so that as soon as a permissive video encoder
lands — or as soon as Meta clarifies the V-JEPA license — we can
ship the artifact mechanically.

The runtime + RPC + CLI surfaces ship empty in wave 1; this harness
populates them in wave 2.

## Targets

| Model | Upstream repo | Params | License | Tier |
|-------|---------------|--------|---------|------|
| V-JEPA 2.1 base | `facebook/vjepa2` | 300M | TBD (license unclear) | B — predictor stripped, custom stem |
| VideoMAE base | `MCG-NJU/videomae-base` | 87M | CC-BY-NC-4.0 | A — clean export, gated by `--accept-non-commercial` |

Tier A: small, well-defined transformer — straight `torch.onnx.export`.
Tier B: custom architecture, may need manual shim around the encoder.

## Layout

```
tools/video-export/
├── README.md          # this file
├── pyproject.toml     # Python deps (torch, transformers, onnx)
├── export.py          # CLI: export <model_id> --out <dir>
├── verify.py          # smoke-test an ONNX file with synthetic frames
├── test_targets.py    # pure-Python tests (no torch)
└── targets.toml       # registry of supported export targets
```

## Local usage

```bash
cd tools/video-export
python -m venv .venv && source .venv/bin/activate
pip install -e .

# Export VideoMAE base to ./out/videomae-base.onnx
python export.py videomae-base --out ./out

# Smoke-test the export
python verify.py ./out/videomae-base.onnx
```

## CI

`.github/workflows/video-export.yml` runs the harness on demand
(`workflow_dispatch`) and runs the pure-Python tests on
`pull_request`. Each successful export becomes a CI artifact that
maintainers can manually upload to `tenzro/video-onnx` on
HuggingFace.

We deliberately don't auto-publish — license clearance for video
encoders is the bottleneck, not export mechanics.

## Adding a new target

1. Add a row to `targets.toml`.
2. If the model uses a non-standard input signature (e.g. a different
   patch embedding scheme), add a per-model export hook in `export.py`.
3. Run locally and confirm `verify.py` passes.
4. Open a PR adding both the artifact (uploaded externally) and the
   catalog entry in `crates/tenzro-model/src/catalog.rs`
   (`get_video_catalog`).
