# Tenzro Video Encoder ONNX Export Harness

Reproducible exporter that takes upstream video encoder foundation
models (V-JEPA 2 / 2.1, VideoMAE, …) and produces single-file ONNX
artifacts compatible with the Tenzro `VideoRuntime`
(`crates/tenzro-model/src/video_runtime.rs`).

## Why this exists

V-JEPA 2 base is MIT-licensed per Meta's model cards
(`facebook/vjepa2-vitl-fpc64-256` and sibling repos), so the licensing
blocker that kept the video catalog empty is resolved. ONNX
export is still non-trivial (custom 3D-conv stem, predictor head must
be skipped) so this harness produces the artifact once, the maintainer
publishes it to `tenzro/vjepa2-vitl-fpc64-256-onnx`, and the catalog
entry in `crates/tenzro-model/src/catalog.rs::get_video_catalog` is
flipped on.

The runtime + RPC + CLI surfaces ship empty; this harness
populates them.

## Targets

| Model | Upstream repo | Params | License | Tier |
|-------|---------------|--------|---------|------|
| V-JEPA 2 ViT-L (base) | `facebook/vjepa2-vitl-fpc64-256` | 300M | MIT | B — predictor stripped via `skip_predictor=True`, custom 3D-conv stem |
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

# Export V-JEPA 2 base to ./out/vjepa2-vitl-fpc64-256.onnx
python export.py vjepa2-vitl-fpc64-256 --out ./out

# Smoke-test the export
python verify.py ./out/vjepa2-vitl-fpc64-256.onnx
```

## CI

`.github/workflows/video-export.yml` runs the harness on demand
(`workflow_dispatch`) and runs the pure-Python tests on
`pull_request`. Each successful export becomes a CI artifact that
maintainers can manually upload to `tenzro/video-onnx` on
HuggingFace.

We deliberately don't auto-publish. The maintainer runs the export,
eyeballs the smoke-test output, and uploads to `tenzro/<bundle>` by
hand.

## Adding a new target

1. Add a row to `targets.toml`.
2. If the model uses a non-standard input signature (e.g. a different
   patch embedding scheme), add a per-model export hook in `export.py`.
3. Run locally and confirm `verify.py` passes.
4. Open a PR adding both the artifact (uploaded externally) and the
   catalog entry in `crates/tenzro-model/src/catalog.rs`
   (`get_video_catalog`).
