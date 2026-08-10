"""Smoke-test a Tenzro video-encoder ONNX artifact.

Loads the ONNX file with onnxruntime, feeds it a synthetic
`[1, T, 3, H, W]` tensor of zeros + Gaussian noise, and checks the
output:
- shape is `[1, D]`
- no NaN/Inf
- numeric variance > 0 (a model that returns a constant is broken)

Exit code 0 if all checks pass, non-zero otherwise.

Usage:
    python verify.py path/to/model.onnx \\
        [--num-frames 16] [--frame-size 224]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import onnx
import onnxruntime as ort


def infer_input_shape(
    model: onnx.ModelProto,
    num_frames_override: int | None,
    frame_size_override: int | None,
) -> tuple[int, int]:
    inp = model.graph.input[0]
    shape = inp.type.tensor_type.shape
    dims = [
        d.dim_value if d.HasField("dim_value") and d.dim_value > 0 else 0
        for d in shape.dim
    ]
    # video: [B, T, 3, H, W]
    num_frames = num_frames_override
    frame_size = frame_size_override
    if num_frames is None and len(dims) >= 2 and dims[1] > 0:
        num_frames = dims[1]
    if frame_size is None and len(dims) >= 5 and dims[3] > 0:
        frame_size = dims[3]
    # Fall back to V-JEPA 2 / VideoMAE defaults.
    return (num_frames or 16, frame_size or 224)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("path", type=Path, help="path to the .onnx file")
    p.add_argument(
        "--num-frames",
        type=int,
        default=None,
        help="override frame count (default: read from model graph)",
    )
    p.add_argument(
        "--frame-size",
        type=int,
        default=None,
        help="override H = W (default: read from model graph)",
    )
    args = p.parse_args(argv)

    if not args.path.is_file():
        print(f"file not found: {args.path}", file=sys.stderr)
        return 2

    print(f"Verifying {args.path}")
    proto = onnx.load(args.path.as_posix())
    onnx.checker.check_model(proto)
    num_frames, frame_size = infer_input_shape(
        proto, args.num_frames, args.frame_size
    )
    print(f"  num_frames = {num_frames}, frame_size = {frame_size}")

    sess = ort.InferenceSession(
        args.path.as_posix(),
        providers=["CPUExecutionProvider"],
    )
    input_name = sess.get_inputs()[0].name

    # Synthetic input: small Gaussian noise. Real-world frames are
    # imagenet-normalized; this isn't (and doesn't need to be) — we're
    # only checking the graph executes and produces non-degenerate output.
    rng = np.random.default_rng(seed=0xCAFE)
    video = rng.standard_normal(
        (1, num_frames, 3, frame_size, frame_size), dtype=np.float32
    )

    outputs = sess.run(None, {input_name: video})
    if not outputs:
        print("  FAIL: model returned no outputs", file=sys.stderr)
        return 1

    out = np.asarray(outputs[0])
    print(f"  output shape = {out.shape}, dtype = {out.dtype}")

    if out.ndim != 2:
        print(
            f"  FAIL: expected output rank 2 ([B, D]), got {out.ndim}",
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

    print(
        f"  output stats: min={out.min():.4f}, max={out.max():.4f}, "
        f"std={out.std():.4f}, dim={out.shape[1]}"
    )
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
