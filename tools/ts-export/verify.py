"""Smoke-test a Tenzro timeseries ONNX artifact.

Loads the ONNX file with onnxruntime, feeds it a synthetic sine wave
of the model's native context length, and checks the output:
- shape is `[1, H]` or `[1, H, Q]`
- no NaN/Inf
- numeric variance > 0 (a model that returns a constant is broken)

Exit code 0 if all checks pass, non-zero otherwise.

Usage:
    python verify.py path/to/model.onnx [--context-len N]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import onnx
import onnxruntime as ort


def infer_context_len(model: onnx.ModelProto, override: int | None) -> int:
    if override is not None:
        return override
    # Look at the first input's static dim if present.
    inp = model.graph.input[0]
    shape = inp.type.tensor_type.shape
    # shape.dim is a list; indices 0=batch, 1=time. Fall back to 2048
    # (Chronos context) if the time dim is dynamic.
    dims = [d.dim_value if d.HasField("dim_value") and d.dim_value > 0 else 0 for d in shape.dim]
    if len(dims) >= 2 and dims[1] > 0:
        return dims[1]
    return 2048


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("path", type=Path, help="path to the .onnx file")
    p.add_argument(
        "--context-len",
        type=int,
        default=None,
        help="override input length (default: read from model graph)",
    )
    args = p.parse_args(argv)

    if not args.path.is_file():
        print(f"file not found: {args.path}", file=sys.stderr)
        return 2

    print(f"Verifying {args.path}")
    proto = onnx.load(args.path.as_posix())
    onnx.checker.check_model(proto)
    ctx_len = infer_context_len(proto, args.context_len)
    print(f"  context_len = {ctx_len}")

    sess = ort.InferenceSession(
        args.path.as_posix(),
        providers=["CPUExecutionProvider"],
    )
    input_name = sess.get_inputs()[0].name

    # Synthetic sine wave with known structure.
    t = np.linspace(0, 4 * np.pi, ctx_len, dtype=np.float32)
    history = np.sin(t).reshape(1, -1)

    outputs = sess.run(None, {input_name: history})
    if not outputs:
        print("  FAIL: model returned no outputs", file=sys.stderr)
        return 1

    out = np.asarray(outputs[0])
    print(f"  output shape = {out.shape}, dtype = {out.dtype}")

    if out.ndim not in (2, 3):
        print(
            f"  FAIL: expected output rank 2 or 3, got {out.ndim}",
            file=sys.stderr,
        )
        return 1
    if out.shape[0] != 1:
        print(f"  FAIL: expected batch dim 1, got {out.shape[0]}", file=sys.stderr)
        return 1

    if not np.isfinite(out).all():
        n_nan = int(np.isnan(out).sum())
        n_inf = int(np.isinf(out).sum())
        print(f"  FAIL: non-finite values (nan={n_nan}, inf={n_inf})", file=sys.stderr)
        return 1

    if float(out.std()) < 1e-9:
        print(
            "  FAIL: output has near-zero variance — model likely broken",
            file=sys.stderr,
        )
        return 1

    print(f"  output stats: min={out.min():.4f}, max={out.max():.4f}, std={out.std():.4f}")
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
