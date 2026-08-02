"""Muon inner optimizer + build_inner_optimizer dispatch."""

from __future__ import annotations

import pytest

torch = pytest.importorskip("torch")
from torch import nn

from tenzro_trainer.muon import (
    Muon,
    build_inner_optimizer,
    partition_parameters,
    zeropower_via_newtonschulz5,
)


def test_newton_schulz_orthogonalizes():
    g = torch.randn(16, 32, generator=torch.Generator().manual_seed(0))
    u = zeropower_via_newtonschulz5(g)
    assert u.shape == g.shape
    # NS-5 with the slope-maximizing coefficients lands singular values in a
    # band around 1 (not exactly 1) — assert the broad band.
    s = torch.linalg.svdvals(u.to(torch.float32))
    assert float(s.min()) > 0.2
    assert float(s.max()) < 1.8


def test_newton_schulz_handles_tall_matrices():
    g = torch.randn(32, 8, generator=torch.Generator().manual_seed(1))
    u = zeropower_via_newtonschulz5(g)
    assert u.shape == g.shape
    s = torch.linalg.svdvals(u.to(torch.float32))
    assert float(s.min()) > 0.2
    assert float(s.max()) < 1.8


def test_newton_schulz_rejects_non_2d():
    with pytest.raises(ValueError):
        zeropower_via_newtonschulz5(torch.randn(4, 4, 4))


class _TinyLm(nn.Module):
    def __init__(self) -> None:
        super().__init__()
        self.embed_tokens = nn.Embedding(16, 8)
        self.proj = nn.Linear(8, 8)
        self.norm = nn.LayerNorm(8)
        self.lm_head = nn.Linear(8, 16)


def test_partition_parameters_tags_embeddings_and_heads_as_fallback():
    model = _TinyLm()
    muon_params, fallback_params = partition_parameters(model)
    named = dict(model.named_parameters())
    assert any(p is named["proj.weight"] for p in muon_params)
    for key in ("embed_tokens.weight", "lm_head.weight", "lm_head.bias",
                "proj.bias", "norm.weight", "norm.bias"):
        assert any(p is named[key] for p in fallback_params), key
    assert len(muon_params) == 1


def test_muon_decreases_loss_on_toy_regression():
    torch.manual_seed(0)
    model = nn.Sequential(nn.Linear(4, 16), nn.Tanh(), nn.Linear(16, 1))
    muon_params, fallback_params = partition_parameters(model)
    opt = Muon(
        [
            {"params": muon_params, "use_muon": True, "lr": 0.02},
            {"params": fallback_params, "use_muon": False, "lr": 1e-3},
        ]
    )
    x = torch.randn(64, 4)
    y = (x.sum(dim=1, keepdim=True) * 0.5) + 0.1
    first = None
    last = None
    for _ in range(50):
        opt.zero_grad(set_to_none=True)
        loss = torch.nn.functional.mse_loss(model(x), y)
        loss.backward()
        opt.step()
        if first is None:
            first = float(loss.detach())
        last = float(loss.detach())
    assert last < first * 0.5


def test_muon_step_handles_conv_filters():
    model = nn.Sequential(nn.Conv2d(3, 4, 3))
    muon_params, _ = partition_parameters(model)
    assert len(muon_params) == 1  # the 4D conv filter
    opt = Muon([{"params": muon_params, "use_muon": True, "lr": 0.02}])
    x = torch.randn(2, 3, 8, 8)
    loss = model(x).square().mean()
    loss.backward()
    opt.step()  # must not raise on the 4D→2D flatten path


def test_build_inner_optimizer_dispatch():
    model = _TinyLm()
    opt = build_inner_optimizer(model, {}, {}, default_lr=1e-4)
    assert isinstance(opt, torch.optim.AdamW)
    assert opt.param_groups[0]["lr"] == 1e-4

    opt = build_inner_optimizer(model, {}, {"inner_optimizer": "sgd"}, default_lr=1e-4)
    assert isinstance(opt, torch.optim.SGD)
    assert opt.param_groups[0]["nesterov"]

    opt = build_inner_optimizer(
        model,
        {"inner_optimizer": "muon"},  # architecture metadata path
        {"learning_rate": 3e-4, "muon_lr": 0.01},
        default_lr=1e-4,
    )
    assert isinstance(opt, Muon)
    assert opt.param_groups[0]["use_muon"] and opt.param_groups[0]["lr"] == 0.01
    assert not opt.param_groups[1]["use_muon"]
    assert opt.param_groups[1]["lr"] == 3e-4

    # Hyperparams override architecture metadata.
    opt = build_inner_optimizer(
        model, {"inner_optimizer": "muon"}, {"inner_optimizer": "adamw"},
        default_lr=1e-4,
    )
    assert isinstance(opt, torch.optim.AdamW)

    with pytest.raises(ValueError):
        build_inner_optimizer(model, {}, {"inner_optimizer": "adafactor"},
                              default_lr=1e-4)


def test_build_inner_optimizer_muon_requires_matrix_params():
    model = nn.Sequential(nn.LayerNorm(4))  # only 1D params
    with pytest.raises(ValueError):
        build_inner_optimizer(model, {}, {"inner_optimizer": "muon"},
                              default_lr=1e-4)
