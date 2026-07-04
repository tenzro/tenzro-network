"""Standalone inner-loop throughput benchmark.

Runs the timeseries reference adapter over a synthetic univariate shard and
reports measured throughput (samples/s, steps/s) for the current hardware.
This exercises the real forward/backward/optimizer path — the same code a
Phase 1 training round drives — without needing a live node or network I/O,
so it can run in CI or a one-shot build job and print a defensible number.

Usage::

    tenzro-trainer-bench --steps 200 --batch-size 8 --warmup 20 --json

The measured figure is the inner-loop wall time only (model construction and
shard load are excluded). "Samples" are mini-batch rows: each is one
``context_patches × patch_size`` forecasting window.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import tempfile
from pathlib import Path
from typing import Any


def _write_synthetic_shard(path: Path, n_points: int) -> str:
    import torch  # deferred: keep import cost out of --help
    import pandas as pd

    t = torch.arange(n_points, dtype=torch.float32)
    series = torch.sin(t * 0.05) + 0.1 * torch.randn(
        n_points, generator=torch.Generator().manual_seed(0)
    )
    pd.DataFrame({"value": series.numpy()}).to_parquet(path)
    return f"file://{path}"


def _torch_device_label() -> str:
    import torch

    if torch.cuda.is_available():
        return f"cuda:{torch.cuda.get_device_name(0)}"
    if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available():
        return "mps"
    return "cpu"


def run_benchmark(
    steps: int,
    batch_size: int,
    warmup: int,
    d_model: int,
    num_layers: int,
    num_heads: int,
    n_points: int,
) -> dict[str, Any]:
    from tenzro_trainer.adapters.timeseries import build_adapter
    from tenzro_trainer.inner_loop import run_inner_loop

    architecture = {
        "metadata": {
            "d_model": d_model,
            "num_layers": num_layers,
            "num_heads": num_heads,
        }
    }
    hyperparams = {"batch_size": batch_size}

    with tempfile.TemporaryDirectory() as td:
        shard = _write_synthetic_shard(Path(td) / "series.parquet", n_points)

        # Warmup: JIT / allocator / cudnn autotune are not part of steady state.
        if warmup > 0:
            adapter = build_adapter(architecture, hyperparams)
            run_inner_loop(adapter, shard, warmup)

        # Measured pass on a fresh adapter (fresh optimizer state).
        adapter = build_adapter(architecture, hyperparams)
        param_count = sum(p.numel() for p in adapter.model().parameters())
        _pre, _post, report = run_inner_loop(adapter, shard, steps)

    return {
        "device": _torch_device_label(),
        "platform": platform.platform(),
        "model": "timeseries-patch-transformer",
        "param_count": param_count,
        "d_model": d_model,
        "num_layers": num_layers,
        "num_heads": num_heads,
        "batch_size": batch_size,
        "steps_measured": report.steps_completed,
        "warmup_steps": warmup,
        "samples_processed": report.samples_processed,
        "wall_seconds": round(report.wall_seconds, 4),
        "samples_per_second": round(report.samples_per_second, 2),
        "steps_per_second": round(report.steps_per_second, 3),
        "final_loss": round(report.final_loss, 6),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tenzro-trainer-bench",
        description="Measure Tenzro Train inner-loop throughput on this machine.",
    )
    parser.add_argument("--steps", type=int, default=200, help="measured inner steps")
    parser.add_argument("--warmup", type=int, default=20, help="unmeasured warmup steps")
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--d-model", type=int, default=256)
    parser.add_argument("--num-layers", type=int, default=4)
    parser.add_argument("--num-heads", type=int, default=4)
    parser.add_argument(
        "--n-points",
        type=int,
        default=16384,
        help="length of the synthetic univariate series",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON only")
    args = parser.parse_args(argv)

    result = run_benchmark(
        steps=args.steps,
        batch_size=args.batch_size,
        warmup=args.warmup,
        d_model=args.d_model,
        num_layers=args.num_layers,
        num_heads=args.num_heads,
        n_points=args.n_points,
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("Tenzro Train inner-loop throughput")
        print(f"  device        : {result['device']}")
        print(f"  model         : {result['model']} ({result['param_count']:,} params)")
        print(f"  batch_size    : {result['batch_size']}")
        print(
            f"  measured      : {result['steps_measured']} steps "
            f"({result['warmup_steps']} warmup) over {result['wall_seconds']}s"
        )
        print(f"  samples/sec   : {result['samples_per_second']}")
        print(f"  steps/sec     : {result['steps_per_second']}")
        print(f"  final_loss    : {result['final_loss']}")
        print()
        print("THROUGHPUT " + json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
