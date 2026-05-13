# Tenzro Timeseries ONNX Export Harness

Reproducible exporter that takes upstream timeseries foundation models
and produces single-file ONNX artifacts compatible with the Tenzro
`TimeseriesRuntime` (`crates/tenzro-model/src/ts_runtime.rs`).

## Why this exists

The catalog (`crates/tenzro-model/src/catalog.rs::get_forecast_catalog`)
points at the community ONNX export at
`pdufour/timesfm-2.5-200m-transformers-onnx`. This harness is the
fallback path. If that community export ever goes offline, falls behind
upstream, or breaks compatibility with the runtime contract, the
maintainer can re-export from the upstream Apache-2.0 checkpoint and
host the artifact under a `tenzro/` HF org.

## Targets

| Model | Upstream repo | Params | License |
|-------|---------------|--------|---------|
| TimesFM 2.5 200M | `google/timesfm-2.5-200m-pytorch` | 200M | Apache 2.0 |

## Layout

```
tools/ts-export/
├── README.md          # this file
├── pyproject.toml     # Python deps (optimum, onnx, torch, transformers)
├── export.py          # CLI: export <model_id> --out <dir>
├── verify.py          # smoke-test an ONNX file with a synthetic series
└── targets.toml       # registry of supported export targets
```

## Local usage

```bash
cd tools/ts-export
python -m venv .venv && source .venv/bin/activate
pip install -e .

# Export TimesFM 2.5 to ./out/timesfm-2.5-200m.onnx
python export.py timesfm-2.5-200m --out ./out

# Smoke-test the export
python verify.py ./out/timesfm-2.5-200m.onnx
```

## CI

`.github/workflows/ts-export.yml` runs the harness on demand
(`workflow_dispatch`). Each successful export becomes a CI artifact
that maintainers can manually upload to `tenzro/timeseries-onnx` on
HuggingFace.

We deliberately don't auto-publish — Apache 2.0 redistribution is
fine, but we want a human in the loop to sanity-check the export
before pointing the runtime at it.

## Adding a new target

1. Add a row to `targets.toml`.
2. If the model uses a non-standard input signature (multivariate,
   patch-based, etc.), add a per-model export hook in `export.py`.
3. Run locally and confirm `verify.py` passes.
4. Open a PR adding both the artifact (uploaded externally) and the
   catalog entry in `crates/tenzro-model/src/catalog.rs`
   (`get_forecast_catalog`).
