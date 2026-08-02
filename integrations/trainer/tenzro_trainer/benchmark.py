"""Standalone inner-loop throughput benchmark.

Two modalities:

* ``--modality timeseries`` (default) runs the timeseries reference adapter
  over a synthetic univariate shard.
* ``--modality language`` runs a **real PEFT LoRA fine-tune** of a
  decoder-only LM: the base is frozen, PEFT injects low-rank adapter
  matrices, and only those matrices carry gradient — so the reported
  ``adapter_delta_bytes`` is the exact outer-gradient payload a
  communication-efficient LoRA round transmits. The default backbone is a
  small Qwen3-family config built locally (no HuggingFace Hub download) so
  the figure is reproducible in CI; ``--hf-repo`` opts into a real catalog
  download.

Both paths exercise the same real forward/backward/optimizer code a Phase 1
training round drives — without a live node or network I/O — so either can
run in CI or a one-shot build job and print a defensible number.

Usage::

    tenzro-trainer-bench --steps 200 --batch-size 8 --warmup 20 --json
    tenzro-trainer-bench --modality language --steps 40 --lora-rank 16 --json

The measured figure is the inner-loop wall time only (model construction and
shard load are excluded). For timeseries, "samples" are mini-batch rows, each
one ``context_patches × patch_size`` forecasting window; for language, each is
one ``seq_len``-token next-token-prediction window.
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
    import pandas as pd
    import torch  # deferred: keep import cost out of --help

    t = torch.arange(n_points, dtype=torch.float32)
    series = torch.sin(t * 0.05) + 0.1 * torch.randn(
        n_points, generator=torch.Generator().manual_seed(0)
    )
    pd.DataFrame({"value": series.numpy()}).to_parquet(path)
    return f"file://{path}"


def _write_synthetic_text_shard(path: Path, n_chars: int) -> str:
    """A deterministic pseudo-natural-language shard the LM adapter can tokenize.

    A fixed vocabulary cycled through a seeded permutation — enough token
    variety for a next-token-prediction loss to move, with no external corpus
    download. The adapter one-shot-tokenizes this file.
    """
    import random

    words = (
        ["the", "network", "trains", "a", "model", "over", "shards", "each", "trainer", "packages", "an", "outer", "gradient", "the", "syncer", "aggregates", "a", "coordinate", "wise", "mean", "of", "adapter", "deltas", "low", "rank", "matrices", "carry", "the", "update", "while", "the", "base", "stays", "frozen"]
    )
    rng = random.Random(0)
    out: list[str] = []
    total = 0
    while total < n_chars:
        w = words[rng.randrange(len(words))]
        out.append(w)
        total += len(w) + 1
    path.write_text(" ".join(out), encoding="utf-8")
    return f"file://{path}"


def _small_qwen3_config(hidden_size: int, num_layers: int, num_heads: int):
    """A locally-built small Qwen3 config — a real architecture, no Hub download.

    Uses the same ``Qwen3`` config class the catalog default (``Qwen3-0.6B``)
    instantiates, shrunk so the LoRA fine-tune runs in seconds on CPU. The
    resulting model is a genuine decoder-only causal LM: PEFT wraps it exactly
    as it would the full-size catalog member.
    """
    from transformers import AutoConfig

    return AutoConfig.for_model(
        "qwen3",
        hidden_size=hidden_size,
        intermediate_size=hidden_size * 2,
        num_hidden_layers=num_layers,
        num_attention_heads=num_heads,
        num_key_value_heads=num_heads,
        vocab_size=4096,
        max_position_embeddings=2048,
        tie_word_embeddings=True,
    )


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


def _build_lora_language_adapter(
    hf_repo: str | None,
    hidden_size: int,
    num_layers: int,
    num_heads: int,
    lora_rank: int,
    seq_len: int,
    batch_size: int,
    device: str,
):
    """A real PEFT-LoRA language adapter over a frozen decoder-only base.

    When ``hf_repo`` is set the catalog member is downloaded and wrapped;
    otherwise a small Qwen3 config is instantiated locally (no download). In
    both cases PEFT freezes the base and injects the low-rank A/B matrices —
    the same code path :func:`tenzro_trainer.adapters.language.build_adapter`
    runs for a production LoRA task — so only the adapter matrices are
    trainable and only their delta is snapshotted.
    """
    import torch
    from peft import LoraConfig, get_peft_model
    from transformers import AutoModelForCausalLM, AutoTokenizer

    from tenzro_trainer.adapters.language import LanguageAdapter, lora_factor_names
    from tenzro_trainer.muon import build_inner_optimizer

    if hf_repo:
        tokenizer = AutoTokenizer.from_pretrained(hf_repo, trust_remote_code=True)
        model = AutoModelForCausalLM.from_pretrained(
            hf_repo, torch_dtype=torch.float32, trust_remote_code=True
        ).to(device)
        vocab_size = model.config.vocab_size
    else:
        config = _small_qwen3_config(hidden_size, num_layers, num_heads)
        model = AutoModelForCausalLM.from_config(config).to(device)
        vocab_size = config.vocab_size
        tokenizer = _ByteVocabTokenizer(vocab_size)

    peft_config = LoraConfig(
        r=lora_rank,
        lora_alpha=2 * lora_rank,
        lora_dropout=0.0,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
        bias="none",
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, peft_config)
    a_names, b_names = lora_factor_names(model)
    opt = build_inner_optimizer(model, {}, {"learning_rate": 1e-4}, default_lr=1e-4)
    adapter = LanguageAdapter(
        _model=model,
        _optimizer=opt,
        _tokenizer=tokenizer,
        seq_len=seq_len,
        batch_size=batch_size,
        device=device,
        lora_alternating=False,
        _lora_a_names=a_names,
        _lora_b_names=b_names,
    )
    return adapter, vocab_size


class _ByteVocabTokenizer:
    """Minimal whitespace-hash tokenizer for the download-free language bench.

    Maps each whitespace token to a stable id in ``[0, vocab_size)`` so the
    synthetic shard tokenizes without a real BPE model. Only the calling
    convention the adapter uses (``tok(text, return_tensors="pt",
    add_special_tokens=False).input_ids``) is implemented.
    """

    def __init__(self, vocab_size: int) -> None:
        self._vocab_size = vocab_size

    def __call__(self, text: str, return_tensors=None, add_special_tokens=False, truncation=False):
        import hashlib

        import torch

        ids = [
            int.from_bytes(hashlib.sha256(tok.encode()).digest()[:4], "little") % self._vocab_size
            for tok in text.split()
        ]

        class _Encoded:
            input_ids = torch.tensor([ids], dtype=torch.long)

        return _Encoded()


def run_lora_benchmark(
    steps: int,
    warmup: int,
    batch_size: int,
    seq_len: int,
    lora_rank: int,
    hidden_size: int,
    num_layers: int,
    num_heads: int,
    hf_repo: str | None,
    n_chars: int,
) -> dict[str, Any]:

    from tenzro_trainer.gradient import (
        compute_outer_delta,
        partition_state_dict,
        serialize_fragment,
    )
    from tenzro_trainer.inner_loop import run_inner_loop
    from tenzro_trainer.types import GradientQuantization

    device = _torch_device_label()
    device = "cpu" if device.startswith("cpu") else ("cuda" if device.startswith("cuda") else "cpu")

    with tempfile.TemporaryDirectory() as td:
        shard = _write_synthetic_text_shard(Path(td) / "corpus.txt", n_chars)

        if warmup > 0:
            adapter, _ = _build_lora_language_adapter(
                hf_repo, hidden_size, num_layers, num_heads,
                lora_rank, seq_len, batch_size, device,
            )
            run_inner_loop(adapter, shard, warmup)

        adapter, _ = _build_lora_language_adapter(
            hf_repo, hidden_size, num_layers, num_heads,
            lora_rank, seq_len, batch_size, device,
        )
        model = adapter.model()
        total_params = sum(p.numel() for p in model.parameters())
        trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)

        pre, post, report = run_inner_loop(adapter, shard, steps)

        # The adapter delta is exactly what a LoRA round transmits: partition
        # it and serialize as the trainer would, then measure the wire bytes.
        delta = compute_outer_delta(pre, post)
        quant = GradientQuantization.none()
        fragments = partition_state_dict(delta, 1)
        delta_bytes = sum(len(serialize_fragment(i, f, quant).payload) for i, f in enumerate(fragments))

    return {
        "device": _torch_device_label(),
        "platform": platform.platform(),
        "model": hf_repo or f"qwen3-small(h={hidden_size},l={num_layers})",
        "fine_tune": "lora",
        "lora_rank": lora_rank,
        "param_count": total_params,
        "trainable_param_count": trainable_params,
        "trainable_pct": round(100.0 * trainable_params / total_params, 4) if total_params else 0.0,
        "adapter_delta_bytes": delta_bytes,
        "seq_len": seq_len,
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
    parser.add_argument(
        "--modality",
        choices=["timeseries", "language"],
        default="timeseries",
        help="timeseries patch-transformer, or a real PEFT-LoRA LM fine-tune",
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
        help="[timeseries] length of the synthetic univariate series",
    )
    # Language / LoRA knobs.
    parser.add_argument("--seq-len", type=int, default=128, help="[language] tokens per window")
    parser.add_argument("--lora-rank", type=int, default=16, help="[language] LoRA rank r")
    parser.add_argument(
        "--hf-repo",
        default=None,
        help="[language] catalog LM to download; omit for a download-free small config",
    )
    parser.add_argument(
        "--n-chars",
        type=int,
        default=200_000,
        help="[language] length of the synthetic text shard",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON only")
    args = parser.parse_args(argv)

    if args.modality == "language":
        result = run_lora_benchmark(
            steps=args.steps,
            warmup=args.warmup,
            batch_size=args.batch_size,
            seq_len=args.seq_len,
            lora_rank=args.lora_rank,
            hidden_size=args.d_model,
            num_layers=args.num_layers,
            num_heads=args.num_heads,
            hf_repo=args.hf_repo,
            n_chars=args.n_chars,
        )
    else:
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
    elif args.modality == "language":
        print("Tenzro Train LoRA fine-tune throughput")
        print(f"  device        : {result['device']}")
        print(f"  model         : {result['model']} ({result['param_count']:,} params)")
        print(
            f"  trainable     : {result['trainable_param_count']:,} "
            f"({result['trainable_pct']}% of total, LoRA r={result['lora_rank']})"
        )
        print(f"  delta/round   : {result['adapter_delta_bytes']:,} bytes (adapter only)")
        print(f"  batch×seq     : {result['batch_size']} × {result['seq_len']}")
        print(
            f"  measured      : {result['steps_measured']} steps "
            f"({result['warmup_steps']} warmup) over {result['wall_seconds']}s"
        )
        print(f"  samples/sec   : {result['samples_per_second']}")
        print(f"  steps/sec     : {result['steps_per_second']}")
        print(f"  final_loss    : {result['final_loss']}")
        print()
        print("LORA_BENCH " + json.dumps(result))
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
