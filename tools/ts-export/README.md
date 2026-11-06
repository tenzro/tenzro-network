# Tenzro Timeseries ONNX Export Harness

Reproducible exporter that takes upstream timeseries foundation models
and produces single-file ONNX artifacts compatible with the Tenzro
`TimeseriesRuntime` (`crates/tenzro-model/src/ts_runtime.rs`).

## Why this exists

The catalog (`crates/tenzro-catalog/seed/onnx-forecast.json`)
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
| Chronos-2 small | `autogluon/chronos-2-small` @ `ddec0131` | 28M | Apache 2.0 |
| Chronos-2 | `amazon/chronos-2` @ `29ec3766` | 120M | Apache 2.0 |
| TiRex-2 | `NX-AI/TiRex-2` @ `05e5b26d` | 95M | Apache 2.0 |
| Toto 2.0 22M | `Datadog/Toto-2.0-22m` @ `685e4ae3` | 22M | Apache 2.0 |
| Toto 2.0 313M | `Datadog/Toto-2.0-313m` @ `a7bab288` | 313M | Apache 2.0 |

## Chronos-2

`python export.py chronos-2-small --expect-sha256 <sha>` exports the official
weights at the pinned revision into the contract the runtime's
`Chronos2Forecast` reads (`context`, `group_ids`, f32 `attention_mask`,
`future_covariates`, `future_covariates_mask` -> `quantile_preds`
`[B, 13, 672]`). With the toolchain in `requirements-lock.txt` (Python 3.14,
torch 2.9.0 CPU, chronos-forecasting 2.3.2) two runs write byte-identical
files:

| Target | Bytes | SHA-256 |
|---|---|---|
| `chronos-2-small` | 112053222 | `a35143f52382c6b8e5d4f614e7bd89b92a91a617eda5680818035930f7176ca2` |
| `chronos-2` | 478485742 | `9d82ed245ee8a9feaba401dac203f91d7cbb49639da29f78c43e1189adbc284b` |

The export's quantiles match the PyTorch model to within 6e-6 of the series
range on 256 to 2048-step series.

## TiRex-2 and Toto 2.0

Both export to the single-input contract `GenericForecast` reads:
`context [1, 2048]` -> `quantiles [1, H, 9]` (levels 0.1 to 0.9, median at
index 4). TiRex-2 (`H = 320`) differences a trending series before the
forward pass; the graph runs the raw and the differenced path and selects
with the checkpoint's trend test computed in the graph. Toto 2.0 (`H = 768`)
decodes the whole horizon in one block. With the toolchain in
`requirements-lock-tirex2-toto2.txt` (Python 3.14, torch 2.14.1 CPU) two runs
write byte-identical files:

| Target | Bytes | SHA-256 |
|---|---|---|
| `tirex-2` | 198691921 | `a95ae626598600c409b213de4c0d063fcd77fd2f84dafa4639c2cfecd2895ebe` |
| `toto-2.0-22m` | 90219882 | `31e825b736508dd79ff7fb7796c7bc18733e7a25cb4024e0bea94f2ce02fc423` |
| `toto-2.0-313m` | 1254238782 | `7cd635b84f22e80d78e69b9e010ec05ebe071b6cae51eeb69b3f15cda9d9e8c2` |

`python parity.py <target> <file.onnx>` compares the export with the upstream
package on CPU: worst quantile difference 2.8e-4 (TiRex-2) and 5.4e-6
(Toto 2.0) of the series range, on seasonal, trending, random-walk and
left-padded short series.

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
   catalog entry in `crates/tenzro-catalog/seed/onnx-forecast.json`.
