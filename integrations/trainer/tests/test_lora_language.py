"""LoRA-aware language adapter helpers — no HF download or PEFT required.

Exercises the two protocol-visible LoRA behaviors on synthetic modules whose
parameter names mimic PEFT's ``...lora_A.<adapter>.weight`` /
``...lora_B.<adapter>.weight`` convention:

* ``lora_factor_names`` splits trainable params into A / B factor lists.
* ``set_round`` performs the alternating low-rank freeze — B trains on even
  rounds, A on odd — so each round's transmitted delta is a single factor.
"""

from __future__ import annotations

import pytest

torch = pytest.importorskip("torch")
from torch import nn

from tenzro_trainer.adapters.language import (
    LanguageAdapter,
    lora_factor_names,
)
from tenzro_trainer.inner_loop import (
    snapshot_state,
    trainable_param_names,
)


class _LoraLinear(nn.Module):
    """A frozen base plus a PEFT-named low-rank A/B pair."""

    def __init__(self, in_f: int = 8, out_f: int = 8, rank: int = 2) -> None:
        super().__init__()
        self.base_layer = nn.Linear(in_f, out_f, bias=False)
        # PEFT names factors ...lora_A.default.weight / ...lora_B.default.weight
        self.lora_A = nn.ModuleDict({"default": nn.Linear(in_f, rank, bias=False)})
        self.lora_B = nn.ModuleDict({"default": nn.Linear(rank, out_f, bias=False)})
        # Frozen base — LoRA/QLoRA only trains the adapters.
        self.base_layer.weight.requires_grad_(False)


class _LoraModel(nn.Module):
    def __init__(self) -> None:
        super().__init__()
        self.q_proj = _LoraLinear()
        self.v_proj = _LoraLinear()


def _lora_adapter(model: nn.Module, alternating: bool = True) -> LanguageAdapter:
    a_names, b_names = lora_factor_names(model)
    return LanguageAdapter(
        _model=model,
        _optimizer=torch.optim.SGD(
            [p for p in model.parameters() if p.requires_grad], lr=0.1
        ),
        _tokenizer=None,
        seq_len=4,
        batch_size=2,
        device="cpu",
        lora_alternating=alternating,
        _lora_a_names=a_names,
        _lora_b_names=b_names,
    )


def test_lora_factor_names_splits_a_and_b():
    model = _LoraModel()
    a_names, b_names = lora_factor_names(model)
    assert a_names == [
        "q_proj.lora_A.default.weight",
        "v_proj.lora_A.default.weight",
    ]
    assert b_names == [
        "q_proj.lora_B.default.weight",
        "v_proj.lora_B.default.weight",
    ]
    # The frozen base is neither an A nor a B factor.
    both = set(a_names) | set(b_names)
    assert "q_proj.base_layer.weight" not in both
    assert "v_proj.base_layer.weight" not in both


def test_lora_snapshot_excludes_frozen_base():
    """Only the trainable adapter matrices land in the outer-gradient snapshot."""
    model = _LoraModel()
    trainable = trainable_param_names(model)
    assert "q_proj.base_layer.weight" not in trainable
    assert "q_proj.lora_A.default.weight" in trainable
    snap = snapshot_state(model)
    assert set(snap) == trainable
    assert all("base_layer" not in k for k in snap)


def test_set_round_even_trains_b_only():
    model = _LoraModel()
    adapter = _lora_adapter(model)
    adapter.set_round(0)  # even → freeze A, train B
    params = dict(model.named_parameters())
    assert not params["q_proj.lora_A.default.weight"].requires_grad
    assert not params["v_proj.lora_A.default.weight"].requires_grad
    assert params["q_proj.lora_B.default.weight"].requires_grad
    assert params["v_proj.lora_B.default.weight"].requires_grad
    # Only the B factor is snapshotted → only B is transmitted this round.
    assert all("lora_A" not in k for k in snapshot_state(model))


def test_set_round_odd_trains_a_only():
    model = _LoraModel()
    adapter = _lora_adapter(model)
    adapter.set_round(1)  # odd → freeze B, train A
    params = dict(model.named_parameters())
    assert params["q_proj.lora_A.default.weight"].requires_grad
    assert not params["q_proj.lora_B.default.weight"].requires_grad
    assert all("lora_B" not in k for k in snapshot_state(model))


def test_set_round_is_noop_without_alternating():
    model = _LoraModel()
    adapter = _lora_adapter(model, alternating=False)
    before = {n: p.requires_grad for n, p in model.named_parameters()}
    adapter.set_round(0)
    after = {n: p.requires_grad for n, p in model.named_parameters()}
    assert before == after
