"""MoE-aware language adapter helpers — no HF download required."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

torch = pytest.importorskip("torch")
from torch import nn  # noqa: E402

from tenzro_trainer.adapters.language import (  # noqa: E402
    LanguageAdapter,
    is_moe_config,
    moe_parameter_names,
)


def test_is_moe_config_covers_catalog_attribute_names():
    assert is_moe_config(SimpleNamespace(num_experts=8))  # Qwen3-MoE
    assert is_moe_config(SimpleNamespace(num_local_experts=8))  # Mixtral-style
    assert is_moe_config(SimpleNamespace(n_routed_experts=64))  # DeepSeek V3
    assert is_moe_config(SimpleNamespace(moe_intermediate_size=768))  # Qwen2-MoE
    assert not is_moe_config(SimpleNamespace(hidden_size=1024))
    assert not is_moe_config(SimpleNamespace(num_experts=0))
    assert not is_moe_config(SimpleNamespace(num_experts=None))
    assert not is_moe_config(SimpleNamespace(num_experts="8"))


class _TinyMoeBlock(nn.Module):
    """Qwen3-MoE-shaped naming: mlp.gate router + mlp.experts.<i> experts."""

    def __init__(self) -> None:
        super().__init__()
        self.gate = nn.Linear(8, 4, bias=False)
        self.experts = nn.ModuleList(nn.Linear(8, 8) for _ in range(4))


class _TinyMoeModel(nn.Module):
    def __init__(self) -> None:
        super().__init__()
        self.embed_tokens = nn.Embedding(16, 8)
        self.mlp = _TinyMoeBlock()
        self.lm_head = nn.Linear(8, 16, bias=False)


def test_moe_parameter_names_split():
    model = _TinyMoeModel()
    expert_names, router_names = moe_parameter_names(model)
    assert expert_names == [f"mlp.experts.{i}.{p}" for i in range(4)
                            for p in ("weight", "bias")]
    assert router_names == ["mlp.gate.weight"]
    # Embeddings / heads are neither experts nor routers.
    all_moe = set(expert_names) | set(router_names)
    assert "embed_tokens.weight" not in all_moe
    assert "lm_head.weight" not in all_moe


class _AuxLossLm(nn.Module):
    """Returns a CausalLMOutput-shaped object with an aux_loss, like a MoE HF
    model with output_router_logits=True."""

    def __init__(self, vocab: int = 16, aux: float | None = 0.25) -> None:
        super().__init__()
        self.proj = nn.Linear(8, vocab)
        self.embed = nn.Embedding(vocab, 8)
        self._aux = aux

    def forward(self, input_ids: "torch.Tensor") -> SimpleNamespace:
        logits = self.proj(self.embed(input_ids))
        aux = (
            None
            if self._aux is None
            else self.proj.weight.square().mean() * self._aux
        )
        return SimpleNamespace(logits=logits, aux_loss=aux)


def _adapter(model: nn.Module) -> LanguageAdapter:
    return LanguageAdapter(
        _model=model,
        _optimizer=torch.optim.SGD(model.parameters(), lr=0.1),
        _tokenizer=None,
        seq_len=4,
        batch_size=2,
        device="cpu",
    )


def test_compute_loss_adds_router_aux_loss():
    torch.manual_seed(0)
    x = torch.randint(0, 16, (2, 4))
    y = torch.randint(0, 16, (2, 4))

    with_aux = _AuxLossLm(aux=0.25)
    without_aux = _AuxLossLm(aux=None)
    without_aux.load_state_dict(with_aux.state_dict())

    loss_aux = _adapter(with_aux).compute_loss((x, y))
    loss_ce = _adapter(without_aux).compute_loss((x, y))
    expected_aux = with_aux.proj.weight.square().mean() * 0.25
    assert torch.allclose(loss_aux, loss_ce + expected_aux)
    # The aux term keeps a gradient path back to the router-side weights.
    loss_aux.backward()
    assert with_aux.proj.weight.grad is not None
