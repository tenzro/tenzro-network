"""Tenzro timeseries ONNX export harness.

Usage:
    python export.py <target_id> [--out <dir>] [--opset 17]

Each target's architecture is dispatched to a dedicated export function.
The output is always a single-file ONNX with shape `[1, context_len]
-> [1, horizon]` or `[1, horizon, n_quantiles]` so the Tenzro
`TimeseriesRuntime::GenericForecast` adapter can load it without
per-model tweaks.

Supported architectures:
- chronos-bolt: T5 encoder + linear quantile head (Apache 2.0, Amazon).
- chronos-2:    T5-derived encoder + multivariate quantile head with
                covariate channel (Apache 2.0, Amazon, Oct 2025).
- ttm:          Granite Tiny TimeMixer, patch-based (Apache 2.0, IBM).
- timesfm:      Google TimesFM 2.5, patch decoder (Apache 2.0, Google).

`ttm` and `timesfm` use a hand-rolled torch.onnx.export wrapper because
their published `forward()` signatures don't match the
`[B, T] -> [B, H]` shape the runtime expects. Wrapper modules adapt the
real model's I/O to the runtime's contract before tracing.
"""

from __future__ import annotations

import argparse
import dataclasses
import sys
from pathlib import Path

try:
    import tomllib  # py3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

import torch


# ──────────────────────────────────────────────────────────────────────
# Target registry
# ──────────────────────────────────────────────────────────────────────


@dataclasses.dataclass(frozen=True)
class Target:
    id: str
    hf_repo: str
    arch: str
    license: str
    params: str
    context_length: int
    max_horizon: int
    n_quantiles: int
    notes: str


def load_targets(path: Path | None = None) -> dict[str, Target]:
    here = Path(__file__).resolve().parent
    targets_path = path or (here / "targets.toml")
    with targets_path.open("rb") as f:
        raw = tomllib.load(f)
    out: dict[str, Target] = {}
    for entry in raw.get("target", []):
        t = Target(**entry)
        out[t.id] = t
    return out


# ──────────────────────────────────────────────────────────────────────
# Architecture-specific export functions
# ──────────────────────────────────────────────────────────────────────


def export_chronos_bolt(target: Target, out_path: Path, opset: int) -> Path:
    """Export Chronos-Bolt small/base.

    Chronos-Bolt is a T5-derived encoder that takes a univariate context
    (already scaled by the model's internal Mean Scaler) and emits
    `[B, n_quantiles, H]` quantile predictions. We wrap it so the ONNX
    sees `[B, T] -> [B, H, Q]` (transpose at the end so the time axis
    comes before the quantile axis, matching the runtime's expected
    layout for `[1, T, Q]` tensors).
    """
    from transformers import AutoModelForSeq2SeqLM

    print(f"  → loading {target.hf_repo} (this is the heaviest step)")
    model = AutoModelForSeq2SeqLM.from_pretrained(
        target.hf_repo,
        torch_dtype=torch.float32,
        trust_remote_code=True,  # Chronos-Bolt ships custom modeling code
    )
    model.eval()

    class ChronosWrapper(torch.nn.Module):
        def __init__(self, inner: torch.nn.Module, horizon: int):
            super().__init__()
            self.inner = inner
            self.horizon = horizon

        def forward(self, context: torch.Tensor) -> torch.Tensor:
            # Chronos-Bolt's `predict` returns [B, Q, H]; transpose to
            # [B, H, Q] for the runtime.
            quantiles = self.inner.predict(
                context=context, prediction_length=self.horizon
            )
            return quantiles.transpose(1, 2).contiguous()

    wrapper = ChronosWrapper(model, target.max_horizon).eval()
    dummy = torch.randn(1, target.context_length, dtype=torch.float32)

    print(f"  → tracing to ONNX (opset={opset})")
    torch.onnx.export(
        wrapper,
        (dummy,),
        out_path.as_posix(),
        input_names=["context"],
        output_names=["quantiles"],
        dynamic_axes={
            "context": {0: "batch"},
            "quantiles": {0: "batch"},
        },
        opset_version=opset,
        do_constant_folding=True,
    )
    return out_path


def export_chronos_2(target: Target, out_path: Path, opset: int) -> Path:
    """Export Chronos-2 (Oct 2025).

    Chronos-2 is the multivariate successor to Chronos-Bolt. It accepts
    a univariate target context plus an optional covariate tensor and
    emits `[B, n_quantiles, H]` quantile predictions over the target.
    The exported wrapper takes both inputs and transposes the output to
    `[B, H, Q]` to match the runtime's `[1, T, Q]` layout convention.

    Covariates are passed as `[B, T, C]` where `C=0` is allowed (zero
    covariates → falls back to univariate forecasting). The runtime
    feeds an empty tensor for univariate calls.
    """
    from transformers import AutoModelForSeq2SeqLM

    print(f"  → loading {target.hf_repo} (this is the heaviest step)")
    model = AutoModelForSeq2SeqLM.from_pretrained(
        target.hf_repo,
        torch_dtype=torch.float32,
        trust_remote_code=True,
    )
    model.eval()

    class Chronos2Wrapper(torch.nn.Module):
        def __init__(self, inner: torch.nn.Module, horizon: int):
            super().__init__()
            self.inner = inner
            self.horizon = horizon

        def forward(
            self,
            context: torch.Tensor,
            covariates: torch.Tensor,
        ) -> torch.Tensor:
            # Chronos-2 returns [B, Q, H]; transpose to [B, H, Q].
            quantiles = self.inner.predict(
                context=context,
                covariates=covariates,
                prediction_length=self.horizon,
            )
            return quantiles.transpose(1, 2).contiguous()

    wrapper = Chronos2Wrapper(model, target.max_horizon).eval()
    dummy_context = torch.randn(1, target.context_length, dtype=torch.float32)
    # Trace with one covariate channel; the runtime can pass C=0 (empty)
    # for univariate inference, which broadcasts cleanly through the
    # exported graph.
    dummy_covariates = torch.randn(1, target.context_length, 1, dtype=torch.float32)

    print(f"  → tracing to ONNX (opset={opset})")
    torch.onnx.export(
        wrapper,
        (dummy_context, dummy_covariates),
        out_path.as_posix(),
        input_names=["context", "covariates"],
        output_names=["quantiles"],
        dynamic_axes={
            "context": {0: "batch"},
            "covariates": {0: "batch", 2: "n_covariates"},
            "quantiles": {0: "batch"},
        },
        opset_version=opset,
        do_constant_folding=True,
    )
    return out_path


def export_ttm(target: Target, out_path: Path, opset: int) -> Path:
    """Export Granite Tiny TimeMixer.

    TTM is patch-based and multivariate-capable, but the runtime only
    supports univariate forecasts. We wrap to fix `n_features=1` and
    return `[B, H]` (point forecast — TTM doesn't emit quantiles).
    """
    from transformers import AutoConfig, AutoModelForSeq2SeqLM

    cfg = AutoConfig.from_pretrained(target.hf_repo, trust_remote_code=True)
    print(f"  → loading {target.hf_repo}")
    model = AutoModelForSeq2SeqLM.from_pretrained(
        target.hf_repo,
        torch_dtype=torch.float32,
        trust_remote_code=True,
    )
    model.eval()

    class TtmWrapper(torch.nn.Module):
        def __init__(self, inner: torch.nn.Module, horizon: int):
            super().__init__()
            self.inner = inner
            self.horizon = horizon

        def forward(self, history: torch.Tensor) -> torch.Tensor:
            # history: [B, T] → [B, T, 1] for univariate input.
            x = history.unsqueeze(-1)
            # TTM returns ForecastModelOutput with .prediction_outputs
            # of shape [B, H, n_features]; squeeze back to [B, H].
            out = self.inner(past_values=x).prediction_outputs[..., 0]
            return out

    wrapper = TtmWrapper(model, target.max_horizon).eval()
    dummy = torch.randn(1, target.context_length, dtype=torch.float32)

    print(f"  → tracing to ONNX (opset={opset})")
    torch.onnx.export(
        wrapper,
        (dummy,),
        out_path.as_posix(),
        input_names=["history"],
        output_names=["forecast"],
        dynamic_axes={
            "history": {0: "batch"},
            "forecast": {0: "batch"},
        },
        opset_version=opset,
        do_constant_folding=True,
    )
    _ = cfg
    return out_path


def export_timesfm(target: Target, out_path: Path, opset: int) -> Path:
    """Export TimesFM 2.5 200M.

    TimesFM uses a 32-token patch tokenizer and a decoder-only
    transformer. Tracing the full inference loop (autoregressive patch
    generation) is fragile; instead, we trace the single-shot forecast
    head which Google ships for fixed-horizon evaluation.
    """
    try:
        from timesfm import TimesFmHparams, TimesFmTorch
    except ImportError as e:
        raise RuntimeError(
            "timesfm export requires `pip install timesfm[torch]`. "
            "This dep is intentionally not in pyproject.toml because it "
            "drags in a large optional ecosystem."
        ) from e

    hparams = TimesFmHparams(
        backend="cpu",
        per_core_batch_size=1,
        horizon_len=target.max_horizon,
        context_len=target.context_length,
        num_layers=50,
    )
    print(f"  → loading {target.hf_repo}")
    model = TimesFmTorch(hparams=hparams, repo=target.hf_repo)
    model.load_from_checkpoint()

    class TimesFmWrapper(torch.nn.Module):
        def __init__(self, inner, horizon: int):
            super().__init__()
            self.inner = inner
            self.horizon = horizon

        def forward(self, history: torch.Tensor) -> torch.Tensor:
            # TimesFm returns (mean, quantiles) — quantiles is [B, H, 10].
            _mean, quantiles = self.inner.forecast_on_tensor(
                history, freq=[0]  # 0 = unknown frequency
            )
            return quantiles

    wrapper = TimesFmWrapper(model, target.max_horizon).eval()
    dummy = torch.randn(1, target.context_length, dtype=torch.float32)

    print(f"  → tracing to ONNX (opset={opset})")
    torch.onnx.export(
        wrapper,
        (dummy,),
        out_path.as_posix(),
        input_names=["history"],
        output_names=["quantiles"],
        dynamic_axes={
            "history": {0: "batch"},
            "quantiles": {0: "batch"},
        },
        opset_version=opset,
        do_constant_folding=True,
    )
    return out_path


EXPORTERS = {
    "chronos-bolt": export_chronos_bolt,
    "chronos-2": export_chronos_2,
    "ttm": export_ttm,
    "timesfm": export_timesfm,
}


# ──────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("target_id", help="ID from targets.toml (e.g. 'chronos-bolt-small')")
    p.add_argument(
        "--out",
        type=Path,
        default=Path("./out"),
        help="output directory (default: ./out)",
    )
    p.add_argument(
        "--opset",
        type=int,
        default=17,
        help="ONNX opset version (default: 17 — matches ort 2.x baseline)",
    )
    p.add_argument(
        "--targets-file",
        type=Path,
        default=None,
        help="path to targets.toml (default: alongside this script)",
    )
    args = p.parse_args(argv)

    targets = load_targets(args.targets_file)
    if args.target_id not in targets:
        known = ", ".join(sorted(targets.keys()))
        print(f"Unknown target '{args.target_id}'. Known: {known}", file=sys.stderr)
        return 2

    target = targets[args.target_id]
    if target.arch not in EXPORTERS:
        print(
            f"No exporter wired for arch='{target.arch}'. "
            f"Add one to EXPORTERS in export.py.",
            file=sys.stderr,
        )
        return 2

    args.out.mkdir(parents=True, exist_ok=True)
    out_path = args.out / f"{target.id}.onnx"

    print(f"Exporting {target.id} ({target.hf_repo}) → {out_path}")
    print(f"  arch={target.arch}, params={target.params}, license={target.license}")
    print(f"  context_length={target.context_length}, max_horizon={target.max_horizon}")

    exporter = EXPORTERS[target.arch]
    exporter(target, out_path, args.opset)

    size_mb = out_path.stat().st_size / 1_048_576
    print(f"OK — {out_path} ({size_mb:.1f} MiB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
