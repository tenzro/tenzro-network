"""Tenzro video-encoder ONNX export harness.

Usage:
    python export.py <target_id> [--out <dir>] [--opset 17]

Each target's architecture is dispatched to a dedicated export
function. The output is always a single-file ONNX with shape
`[1, T, 3, H, W] -> [1, D]` so the Tenzro `VideoRuntime` adapter can
load it without per-model tweaks. `T` is the model's native frame
count, `H = W = frame_size`, and `D = embedding_dim` from
targets.toml.

Supported architectures:
- vjepa2:   V-JEPA 2 ViT-L/16 with 3D-conv stem (MIT, Meta). The
            wrapper passes `skip_predictor=True` so only the encoder
            graph is traced.
- videomae: VideoMAE ViT-B/16 with tubelet patch embedding
            (CC-BY-NC-4.0, MCG-NJU).

Both architectures are encoder-only (any predictor / decoder head is
stripped). The wrapper modules adapt the upstream `forward()`
signatures to the runtime's `[1, T, 3, H, W] -> [1, D]` contract.
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
    frame_size: int
    num_frames: int
    fps: int
    embedding_dim: int
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


def export_vjepa2(target: Target, out_path: Path, opset: int) -> Path:
    """Export V-JEPA 2 / 2.1 encoder.

    V-JEPA's published checkpoints contain both the encoder and the
    predictor; we strip the predictor and trace only the encoder so the
    ONNX graph computes a single-pass embedding `[1, T, 3, H, W] -> [1, D]`.

    The 3D-conv stem is custom — `torch.onnx.export` handles it as long
    as `opset >= 17` (Conv3d ops at opset 11+, but tubelet-style
    embeddings need the broader 17 surface for clean tracing).
    """
    from transformers import AutoModel

    print(f"  → loading {target.hf_repo} (this is the heaviest step)")
    model = AutoModel.from_pretrained(
        target.hf_repo,
        torch_dtype=torch.float32,
        trust_remote_code=True,  # V-JEPA ships custom modeling code
    )
    model.eval()

    class VjepaWrapper(torch.nn.Module):
        def __init__(self, inner: torch.nn.Module):
            super().__init__()
            self.inner = inner

        def forward(self, video: torch.Tensor) -> torch.Tensor:
            # video: [B, T, 3, H, W] → encoder returns last_hidden_state
            # of shape [B, N_tokens, D]; mean-pool over tokens to a
            # single embedding [B, D] for the runtime.
            #
            # `skip_predictor=True` drops the JEPA predictor forward so
            # the traced graph contains only the encoder — exactly what
            # the runtime needs for retrieval/similarity embeddings.
            out = self.inner(
                pixel_values_videos=video,
                skip_predictor=True,
            )
            tokens = out.last_hidden_state
            return tokens.mean(dim=1)

    wrapper = VjepaWrapper(model).eval()
    dummy = torch.randn(
        1,
        target.num_frames,
        3,
        target.frame_size,
        target.frame_size,
        dtype=torch.float32,
    )

    print(f"  → tracing to ONNX (opset={opset})")
    torch.onnx.export(
        wrapper,
        (dummy,),
        out_path.as_posix(),
        input_names=["video"],
        output_names=["embedding"],
        dynamic_axes={
            "video": {0: "batch"},
            "embedding": {0: "batch"},
        },
        opset_version=opset,
        do_constant_folding=True,
    )
    return out_path


def export_videomae(target: Target, out_path: Path, opset: int) -> Path:
    """Export VideoMAE encoder.

    VideoMAE uses tubelet patch embedding (3D conv with stride
    `[2, patch, patch]`). We trace just the encoder, dropping the MAE
    pretraining decoder. Output is the [CLS]-equivalent pooled
    embedding, shape `[B, D]`.
    """
    from transformers import VideoMAEModel

    print(f"  → loading {target.hf_repo}")
    model = VideoMAEModel.from_pretrained(
        target.hf_repo,
        torch_dtype=torch.float32,
    )
    model.eval()

    class VideoMaeWrapper(torch.nn.Module):
        def __init__(self, inner: torch.nn.Module):
            super().__init__()
            self.inner = inner

        def forward(self, video: torch.Tensor) -> torch.Tensor:
            # video: [B, T, 3, H, W] → last_hidden_state [B, N, D];
            # mean-pool over the patch axis to [B, D].
            out = self.inner(pixel_values=video)
            return out.last_hidden_state.mean(dim=1)

    wrapper = VideoMaeWrapper(model).eval()
    dummy = torch.randn(
        1,
        target.num_frames,
        3,
        target.frame_size,
        target.frame_size,
        dtype=torch.float32,
    )

    print(f"  → tracing to ONNX (opset={opset})")
    torch.onnx.export(
        wrapper,
        (dummy,),
        out_path.as_posix(),
        input_names=["video"],
        output_names=["embedding"],
        dynamic_axes={
            "video": {0: "batch"},
            "embedding": {0: "batch"},
        },
        opset_version=opset,
        do_constant_folding=True,
    )
    return out_path


EXPORTERS = {
    "vjepa2": export_vjepa2,
    "videomae": export_videomae,
}


# ──────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("target_id", help="ID from targets.toml (e.g. 'videomae-base')")
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
    print(
        f"  frame_size={target.frame_size}, num_frames={target.num_frames}, "
        f"fps={target.fps}, embedding_dim={target.embedding_dim}"
    )

    exporter = EXPORTERS[target.arch]
    exporter(target, out_path, args.opset)

    size_mb = out_path.stat().st_size / 1_048_576
    print(f"OK — {out_path} ({size_mb:.1f} MiB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
