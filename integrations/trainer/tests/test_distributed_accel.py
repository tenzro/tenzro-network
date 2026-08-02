"""Tests for the distributed context, FSDP2 sharding, and acceleration knobs."""

from __future__ import annotations

import os

import pytest

torch = pytest.importorskip("torch")
from torch import nn

from tenzro_trainer.accel import maybe_convert_fp8, resolve_attn_implementation
from tenzro_trainer.distributed import (
    DistContext,
    add_into,
    copy_into,
    full_tensor,
    is_dtensor,
    shard_model_fsdp2,
)
from tenzro_trainer.inner_loop import (
    apply_state_delta,
    load_partial_state,
    snapshot_state,
)

# ---------------------------------------------------------------------------
# accel
# ---------------------------------------------------------------------------


def test_attn_metadata_override_wins():
    assert resolve_attn_implementation({"attn_implementation": "eager"}) == "eager"


def test_attn_falls_back_to_sdpa_without_cuda():
    if torch.cuda.is_available():
        pytest.skip("CUDA present; fallback path not exercised")
    assert resolve_attn_implementation({}) == "sdpa"


def test_fp8_not_requested_is_noop():
    model = nn.Linear(16, 16)
    assert maybe_convert_fp8(model, {}) is model
    assert maybe_convert_fp8(model, {"fp8": False}) is model
    assert maybe_convert_fp8(model, {"fp8": "false"}) is model


def test_fp8_requested_on_cpu_is_noop():
    if torch.cuda.is_available():
        pytest.skip("CUDA present; CPU no-op path not exercised")
    model = nn.Linear(16, 16)
    out = maybe_convert_fp8(model, {"fp8": True})
    assert out is model
    assert isinstance(out, nn.Linear)


# ---------------------------------------------------------------------------
# DistContext
# ---------------------------------------------------------------------------


def test_detect_disabled_without_torchrun_env(monkeypatch):
    monkeypatch.delenv("RANK", raising=False)
    monkeypatch.delenv("WORLD_SIZE", raising=False)
    ctx = DistContext.detect()
    assert not ctx.enabled
    assert ctx.is_primary
    assert ctx.world_size == 1


def test_detect_disabled_for_world_size_one(monkeypatch):
    monkeypatch.setenv("RANK", "0")
    monkeypatch.setenv("WORLD_SIZE", "1")
    ctx = DistContext.detect()
    assert not ctx.enabled


def test_shard_is_noop_when_disabled():
    model = nn.Linear(4, 4)
    ctx = DistContext(enabled=False, rank=0, world_size=1, local_rank=0)
    assert shard_model_fsdp2(model, ctx) is model
    assert not any(is_dtensor(p) for p in model.parameters())


# ---------------------------------------------------------------------------
# DTensor helpers degrade to plain tensors
# ---------------------------------------------------------------------------


def test_helpers_on_plain_tensors():
    t = torch.ones(3, 3)
    assert not is_dtensor(t)
    assert full_tensor(t) is t
    p = torch.zeros(3, 3)
    copy_into(p, t)
    assert torch.equal(p, t)
    add_into(p, t)
    assert torch.equal(p, 2 * t)


# ---------------------------------------------------------------------------
# FSDP2 round-trip on a single-rank gloo group
# ---------------------------------------------------------------------------


class _Tiny(nn.Module):
    def __init__(self):
        super().__init__()
        self.blocks = nn.ModuleList([nn.Linear(8, 8) for _ in range(2)])
        self.head = nn.Linear(8, 4)

    def forward(self, x):
        for b in self.blocks:
            x = torch.relu(b(x))
        return self.head(x)


@pytest.fixture()
def single_rank_group():
    import torch.distributed as dist

    if dist.is_initialized():
        yield
        return
    os.environ.setdefault("MASTER_ADDR", "127.0.0.1")
    os.environ.setdefault("MASTER_PORT", "29511")
    dist.init_process_group(backend="gloo", rank=0, world_size=1)
    yield
    dist.destroy_process_group()


def test_fsdp2_snapshot_load_apply_round_trip(single_rank_group):
    try:
        from torch.distributed.fsdp import fully_shard  # noqa: F401
    except ImportError:
        pytest.skip("torch build lacks FSDP2 fully_shard")

    model = _Tiny()
    reference = {k: v.clone() for k, v in snapshot_state(model).items()}
    ctx = DistContext(enabled=True, rank=0, world_size=1, local_rank=0)
    try:
        model = shard_model_fsdp2(model, ctx)
    except Exception as e:  # pragma: no cover - depends on torch build
        pytest.skip(f"fully_shard unavailable on this torch build: {e}")

    assert any(is_dtensor(p) for p in model.parameters())

    # Snapshot gathers full tensors and matches the pre-shard values.
    snap = snapshot_state(model)
    assert set(snap.keys()) == set(reference.keys())
    for k, v in snap.items():
        assert not is_dtensor(v)
        assert torch.allclose(v.float(), reference[k].float(), atol=1e-6)

    # load_partial_state distributes full tensors back into shards.
    zeros = {k: torch.zeros_like(v) for k, v in snap.items()}
    load_partial_state(model, zeros)
    for v in snapshot_state(model).values():
        assert torch.count_nonzero(v) == 0

    # apply_state_delta adds a full delta into the sharded params.
    apply_state_delta(model, {k: torch.ones_like(v) for k, v in snap.items()})
    for v in snapshot_state(model).values():
        assert torch.allclose(v.float(), torch.ones_like(v).float())
