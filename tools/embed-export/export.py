"""Reproducible ONNX export of sentence-embedding checkpoints.

Usage:
    python export.py <target_id> --out <dir> [--expect-sha256 <model.onnx sha>] [--expected-json <path>]

Encoder checkpoints: the graph takes `input_ids` and `attention_mask` (int64,
`[B, L]`) and returns `sentence_embedding` `[B, D]`, the checkpoint's mean
over the non-pad positions followed by L2 normalisation.

The base weights are fetched at the revision pinned below, the trace runs on
CPU in float32, and the toolchain in `requirements-lock.txt` writes
byte-identical files. `--expected-json` also writes the reference embeddings
from the checkpoint's own pipeline for the runtime's encoder parity tests.
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

import torch


@dataclass(frozen=True)
class Target:
    id: str
    hf_repo: str
    revision: str
    pooling: str  # "mean" | "last"
    query_prompt: str
    document_prompt: str


TARGETS = {
    "nemotron-3-embed-1b": Target(
        id="nemotron-3-embed-1b",
        hf_repo="nvidia/Nemotron-3-Embed-1B-BF16",
        revision="c0c9fea93ea424587517f2c59e20db9f1d6bf615",
        pooling="mean",
        query_prompt="query: ",
        document_prompt="passage: ",
    ),
}

PARITY_QUERIES = [
    "how much protein should a female eat",
    "Write a Python function that counts the frequency of each element in a list of lists.",
]
PARITY_DOCUMENTS = [
    "Definition of summit: the highest point of a mountain.",
    "People with pollen allergy can reduce exposure by staying indoors on dry, windy days.",
    "short",
]


class SentenceEmbedding(torch.nn.Module):
    def __init__(self, inner: torch.nn.Module, pooling: str):
        super().__init__()
        if pooling != "mean":
            raise RuntimeError(f"pooling '{pooling}' is not wired for an encoder")
        self.inner = inner

    def forward(self, input_ids, attention_mask):
        hidden = self.inner(input_ids=input_ids, attention_mask=attention_mask).last_hidden_state
        keep = attention_mask.unsqueeze(-1).to(hidden.dtype)
        pooled = (hidden * keep).sum(dim=1) / keep.sum(dim=1).clamp(min=1.0)
        return torch.nn.functional.normalize(pooled, p=2.0, dim=-1)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 24), b""):
            h.update(chunk)
    return h.hexdigest()


def trace(module, args, out: Path, stem: str, opset: int, input_names, output_names, dynamic_axes) -> None:
    """Trace `module` to `<stem>.onnx` with its weights in `<stem>.onnx_data`."""
    import onnx

    staging = out / f"staging-{stem}"
    staging.mkdir(parents=True, exist_ok=True)
    print(f"  → tracing {stem} to ONNX (opset={opset})")
    with torch.no_grad():
        torch.onnx.export(
            module,
            args,
            (staging / "model.onnx").as_posix(),
            input_names=input_names,
            output_names=output_names,
            dynamic_axes=dynamic_axes,
            opset_version=opset,
            do_constant_folding=True,
            dynamo=False,
        )
    graph = onnx.load((staging / "model.onnx").as_posix(), load_external_data=True)
    onnx.save_model(
        graph,
        (out / f"{stem}.onnx").as_posix(),
        save_as_external_data=True,
        all_tensors_to_one_file=True,
        location=f"{stem}.onnx_data",
        size_threshold=1024,
    )
    del graph
    shutil.rmtree(staging)
    gc.collect()


def export(target: Target, out: Path, opset: int) -> list[Path]:
    from huggingface_hub import snapshot_download
    from transformers import AutoModel

    src = Path(snapshot_download(target.hf_repo, revision=target.revision))
    print(f"  → loading {target.hf_repo}@{target.revision}")
    model = AutoModel.from_pretrained(src, dtype=torch.float32, attn_implementation="eager").eval()
    out.mkdir(parents=True, exist_ok=True)
    if getattr(model.config, "is_causal", True):
        raise RuntimeError("the checkpoint is not marked bidirectional (config.is_causal)")
    ids = torch.tensor([[1, 2, 3, 4, 5, 6, 7, 8]], dtype=torch.int64)
    trace(
        SentenceEmbedding(model, target.pooling).eval(),
        (ids, torch.ones_like(ids)),
        out,
        "model",
        opset,
        ["input_ids", "attention_mask"],
        ["sentence_embedding"],
        {
            "input_ids": {0: "batch", 1: "sequence"},
            "attention_mask": {0: "batch", 1: "sequence"},
            "sentence_embedding": {0: "batch"},
        },
    )
    files = ["model.onnx", "model.onnx_data"]
    del model
    gc.collect()
    shutil.copyfile(src / "tokenizer.json", out / "tokenizer.json")
    return [out / f for f in files + ["tokenizer.json"]]


def write_expected(target: Target, path: Path) -> None:
    from sentence_transformers import SentenceTransformer

    ref = SentenceTransformer(
        target.hf_repo,
        revision=target.revision,
        device="cpu",
        model_kwargs={"dtype": torch.float32, "attn_implementation": "eager"},
    )
    if ref.prompts.get("query") != target.query_prompt or ref.prompts.get("document") != target.document_prompt:
        raise RuntimeError(f"checkpoint prompts {ref.prompts} differ from the pinned template")
    texts = [target.query_prompt + q for q in PARITY_QUERIES] + [target.document_prompt + d for d in PARITY_DOCUMENTS]
    want = ref.encode(texts, normalize_embeddings=True, batch_size=1)
    path.write_text(json.dumps({"texts": texts, "embeddings": want.tolist()}))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("target_id", choices=sorted(TARGETS))
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--opset", type=int, default=17)
    p.add_argument("--expect-sha256", default=None, help="refuse unless model.onnx has this SHA-256")
    p.add_argument("--expected-json", type=Path, default=None)
    p.add_argument("--no-export", action="store_true", help="only write --expected-json")
    args = p.parse_args(argv)
    torch.manual_seed(0)
    torch.use_deterministic_algorithms(True)
    target = TARGETS[args.target_id]
    if args.expected_json is not None:
        write_expected(target, args.expected_json)
    if args.no_export:
        return 0
    files = export(target, args.out, args.opset)
    for path in files:
        print(f"{path.name}: {path.stat().st_size} bytes, sha256 {sha256(path)}")
    if args.expect_sha256 is not None and sha256(files[0]) != args.expect_sha256:
        print(f"the export is not reproducible: expected sha256 {args.expect_sha256}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
