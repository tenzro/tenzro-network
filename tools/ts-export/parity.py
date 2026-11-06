"""Compare an exported forecaster against the upstream package on CPU.

Runs the upstream model (at the revision `targets.toml` pins) and the ONNX
file on the same series and reports, per series, the largest quantile
difference as a fraction of the series range. Series cover a flat-ish
seasonal signal, a strong trend (which takes the differenced path where the
model has one), a random walk and a short history left-padded with its first
value the way the runtime pads.

Usage:
    python parity.py <target_id> <path/to/model.onnx> [--tol 1e-3]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import onnxruntime as ort
import torch

from export import load_targets


def series_set(ctx: int) -> dict[str, np.ndarray]:
    rng = np.random.default_rng(0)
    t = np.arange(ctx, dtype=np.float64)
    short = 300 + 20 * np.sin(np.arange(200) / 7.0) + rng.normal(0, 2, 200)
    return {
        "seasonal": 50 + 10 * np.sin(t / 24.0) + 3 * np.sin(t / 168.0) + rng.normal(0, 0.5, ctx),
        "trend": 0.05 * t + 2 * np.sin(t / 12.0) + rng.normal(0, 0.2, ctx),
        "random_walk": np.cumsum(rng.normal(0, 1, ctx)) + 100,
        "short_padded": np.concatenate([np.full(ctx - 200, short[0]), short]),
    }


def upstream(target, arch: str):
    if arch == "tirex2":
        from tirex2 import TimeseriesType, load_model

        model = load_model(target.hf_repo, device="cpu", hf_kwargs={"revision": target.revision})

        def run(x: np.ndarray) -> np.ndarray:
            ts = TimeseriesType(target=torch.tensor(x, dtype=torch.float32).unsqueeze(0), past_covariates=None, future_covariates=None)
            out = model.model.predict([ts], target.max_horizon)[0]  # [1, Q, H]
            return out[0].transpose(0, 1).numpy()

        return run
    if arch == "toto2":
        from toto2 import Toto2Model

        model = Toto2Model.from_pretrained(target.hf_repo, revision=target.revision).float().eval()

        def run(x: np.ndarray) -> np.ndarray:
            s = torch.tensor(x, dtype=torch.float32).reshape(1, 1, -1)
            with torch.no_grad():
                q = model.forecast(
                    {"target": s, "target_mask": torch.ones_like(s, dtype=torch.bool), "series_ids": torch.zeros(1, 1, dtype=torch.long)},
                    horizon=target.max_horizon,
                    decode_block_size=target.max_horizon,
                    has_missing_values=False,
                )
            return q[:, 0, 0, :].transpose(0, 1).numpy()

        return run
    raise SystemExit(f"no upstream reference for arch '{arch}'")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("target_id")
    p.add_argument("onnx", type=Path)
    p.add_argument("--tol", type=float, default=1e-3, help="max |diff| / series range")
    args = p.parse_args(argv)
    torch.manual_seed(0)
    target = load_targets()[args.target_id]
    ref = upstream(target, target.arch)
    sess = ort.InferenceSession(args.onnx.as_posix(), providers=["CPUExecutionProvider"])
    worst = 0.0
    for name, x in series_set(target.context_length).items():
        want = ref(x)
        got = sess.run(None, {sess.get_inputs()[0].name: x.astype(np.float32)[None, :]})[0][0]
        if got.shape != want.shape:
            print(f"{name}: shape {got.shape} != upstream {want.shape}")
            return 1
        rel = float(np.max(np.abs(got - want)) / (np.ptp(x) or 1.0))
        worst = max(worst, rel)
        print(f"{name}: shape {got.shape} max|diff|/range {rel:.2e} median[0..3] {np.round(got[:3, got.shape[1] // 2], 4).tolist()}")
    print(f"worst {worst:.2e} (tol {args.tol:.0e})")
    return 0 if worst <= args.tol else 1


if __name__ == "__main__":
    sys.exit(main())
