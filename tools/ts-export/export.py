"""Tenzro timeseries ONNX export harness.

Usage:
    python export.py <target_id> [--out <dir>] [--opset 17]

Each target's architecture is dispatched to a dedicated export function.
The output is always a single-file ONNX with shape `[1, context_len]
-> [1, horizon]` or `[1, horizon, n_quantiles]` so the Tenzro
`TimeseriesRuntime::GenericForecast` adapter can load it without
per-model tweaks.

Supported architectures:
- timesfm:      Google TimesFM 2.5, patch decoder (Apache 2.0, Google).

`timesfm` uses a hand-rolled torch.onnx.export wrapper because its
published `forward()` signature doesn't match the `[B, T] -> [B, H, Q]`
shape the runtime expects. The wrapper module adapts the real model's
I/O to the runtime's contract before tracing.
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
    "timesfm": export_timesfm,
}


# ──────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("target_id", help="ID from targets.toml (e.g. 'timesfm-2.5-200m')")
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
