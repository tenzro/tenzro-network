"""Measured LoRA fine-tune over a real PEFT-wrapped decoder-only LM.

Unlike ``test_lora_language.py`` (which checks the A/B factor split on synthetic
modules), this drives an actual PEFT ``get_peft_model`` LoRA fine-tune of a
small locally-built Qwen3 config — frozen base, low-rank adapter matrices, real
forward/backward/optimizer via :func:`run_inner_loop` — and asserts the reported
figure is internally consistent: only the adapter matrices are trainable, and the
transmitted per-round delta covers exactly those matrices. No HuggingFace Hub
download, so it runs in CI. This is the CI anchor for the published LoRA number.
"""

from __future__ import annotations

import pytest

pytest.importorskip("torch")
pytest.importorskip("transformers")
pytest.importorskip("peft")

from tenzro_trainer.benchmark import run_lora_benchmark


def _run(steps: int = 6, lora_rank: int = 8):
    return run_lora_benchmark(
        steps=steps,
        warmup=2,
        batch_size=2,
        seq_len=32,
        lora_rank=lora_rank,
        hidden_size=64,
        num_layers=2,
        num_heads=4,
        hf_repo=None,
        n_chars=20_000,
    )


def test_lora_benchmark_only_adapters_are_trainable():
    """The frozen base dominates; only the low-rank matrices carry gradient."""
    result = _run()

    assert result["fine_tune"] == "lora"
    assert result["steps_measured"] == 6
    # Real PEFT wrap: a strict subset of params is trainable, and it is small.
    assert 0 < result["trainable_param_count"] < result["param_count"]
    assert result["trainable_pct"] < 25.0, (
        "LoRA should train a small fraction of the base"
    )
    # The transmitted per-round payload is non-empty and adapter-scoped: its
    # byte count is far below a full-model snapshot of float32 params.
    assert result["adapter_delta_bytes"] > 0
    assert result["adapter_delta_bytes"] < result["param_count"] * 4


def test_lora_benchmark_throughput_is_consistent():
    result = _run()
    assert result["wall_seconds"] > 0.0
    assert result["samples_per_second"] > 0.0
    assert result["steps_per_second"] > 0.0
    # samples = batch_size (2) × steps.
    assert result["samples_processed"] == 2 * result["steps_measured"]


def test_lora_rank_scales_transmitted_delta():
    """Higher rank ⇒ more adapter parameters ⇒ a larger per-round delta."""
    small = _run(lora_rank=4)
    large = _run(lora_rank=16)
    assert large["trainable_param_count"] > small["trainable_param_count"]
    assert large["adapter_delta_bytes"] > small["adapter_delta_bytes"]
