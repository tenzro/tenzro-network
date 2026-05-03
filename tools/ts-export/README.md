# Tenzro Timeseries ONNX Export Harness

Reproducible exporter that takes upstream timeseries foundation models
(Chronos-Bolt, Granite-TTM, TimesFM 2.5, …) and produces single-file
ONNX artifacts compatible with the Tenzro `TimeseriesRuntime`
(`crates/tenzro-model/src/ts_runtime.rs`).

## Why this exists

As of 2026-04, no first-party ungated ONNX timeseries foundation models
exist on HuggingFace. The upstream repos all ship safetensors only.
Since Apache 2.0 / MIT licensed weights are redistributable, we export
them ourselves and host the ONNX artifacts under a `tenzro/` org so the
runtime catalog (`crates/tenzro-model/src/catalog.rs::get_timeseries_catalog`,
when populated) can point to them.

## Targets

| Model | Upstream repo | Params | License | Tier |
|-------|---------------|--------|---------|------|
| Chronos-Bolt small | `amazon/chronos-bolt-small` | 48M | Apache 2.0 | A — first |
| Chronos-Bolt base | `amazon/chronos-bolt-base` | 205M | Apache 2.0 | A |
| Chronos-2 | `amazon/chronos-2` | 120M | Apache 2.0 | B — multivariate w/ covariates |
| Granite-TTM r2 (512) | `ibm-granite/granite-timeseries-ttm-r2` | 1M | Apache 2.0 | B |
| TimesFM 2.5 200M | `google/timesfm-2.5-200m-pytorch` | 200M | Apache 2.0 | B |

Tier A: small, well-defined transformer — straight `optimum-cli` path.
Tier B: custom architecture, may need manual `torch.onnx.export` shim.

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

# Export Chronos-Bolt small to ./out/chronos-bolt-small.onnx
python export.py chronos-bolt-small --out ./out

# Smoke-test the export
python verify.py ./out/chronos-bolt-small.onnx
```

## CI

`.github/workflows/ts-export.yml` runs the harness on demand
(`workflow_dispatch`). Each successful export becomes a CI artifact
that maintainers can manually upload to `tenzro/timeseries-onnx` on
HuggingFace.

We deliberately don't auto-publish — Apache 2.0 redistribution is
fine, but we want a human in the loop to sanity-check the export
before it lands in the catalog and the runtime starts pointing
real users at it.

## Adding a new target

1. Add a row to `targets.toml`.
2. If the model uses a non-standard input signature (multivariate,
   patch-based, etc.), add a per-model export hook in `export.py`.
3. Run locally and confirm `verify.py` passes.
4. Open a PR adding both the artifact (uploaded externally) and the
   catalog entry in `crates/tenzro-model/src/catalog.rs`.
