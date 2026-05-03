"""Language trainer adapter (Phase 1 stub).

The language modality is *protocol-supported* in Phase 1 — gradient packaging,
RPC plumbing, and aggregation work identically — but the in-process reference
model here is a small GPT-style decoder for smoke-tests, not the production
backbone. Real deployments are expected to override :func:`build_adapter` with
a Llama / Mistral / T5 implementation that loads weights via HuggingFace
transformers and (optionally) wraps them in FSDP2.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable

try:
    import torch
    from torch import nn
except ImportError:  # pragma: no cover
    torch = None  # type: ignore[assignment]
    nn = None  # type: ignore[assignment]


log = logging.getLogger(__name__)


class _TinyDecoderLM(nn.Module if nn is not None else object):  # type: ignore[misc]
    """4-layer causal decoder over a fixed byte vocabulary (256)."""

    def __init__(self, d_model: int = 256, num_layers: int = 4, num_heads: int = 4, vocab: int = 256):
        super().__init__()
        self.embed = nn.Embedding(vocab, d_model)
        self.pos = nn.Parameter(torch.zeros(512, d_model))
        nn.init.trunc_normal_(self.pos, std=0.02)
        layer = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=num_heads, batch_first=True, activation="gelu"
        )
        self.blocks = nn.TransformerEncoder(layer, num_layers=num_layers)
        self.head = nn.Linear(d_model, vocab)

    def forward(self, tokens: "torch.Tensor") -> "torch.Tensor":
        b, t = tokens.shape
        h = self.embed(tokens) + self.pos[:t].unsqueeze(0)
        mask = nn.Transformer.generate_square_subsequent_mask(t).to(h.device)
        h = self.blocks(h, mask=mask)
        return self.head(h)


@dataclass
class LanguageAdapter:
    _model: "_TinyDecoderLM"
    _optimizer: "torch.optim.Optimizer"
    seq_len: int = 64
    batch_size: int = 4

    def model(self) -> "torch.nn.Module":
        return self._model

    def optimizer(self) -> "torch.optim.Optimizer":
        return self._optimizer

    def shard_batches(self, shard_uri: str) -> Iterable[object]:
        if torch is None:
            raise RuntimeError("PyTorch is required")
        path = shard_uri[len("file://") :] if shard_uri.startswith("file://") else shard_uri
        if shard_uri.startswith(("ipfs://", "ar://", "https://", "http://")):
            raise NotImplementedError(
                f"remote shard scheme not supported in Phase 1 demo adapter: {shard_uri}"
            )
        with open(path, "rb") as f:
            data = f.read()
        if len(data) < self.seq_len + 1:
            raise ValueError(f"language shard {path!r} too small")
        tokens = torch.tensor(list(data), dtype=torch.long)
        rng = torch.Generator()
        rng.manual_seed(0)
        while True:
            idx = torch.randint(
                0, tokens.shape[0] - self.seq_len - 1, (self.batch_size,), generator=rng
            )
            x = torch.stack([tokens[i : i + self.seq_len] for i in idx])
            y = torch.stack([tokens[i + 1 : i + 1 + self.seq_len] for i in idx])
            yield x, y

    def compute_loss(self, batch: object) -> "torch.Tensor":
        if torch is None:
            raise RuntimeError("PyTorch is required")
        x, y = batch  # type: ignore[misc]
        logits = self._model(x)
        return torch.nn.functional.cross_entropy(
            logits.reshape(-1, logits.shape[-1]), y.reshape(-1)
        )


def build_adapter(
    architecture: dict[str, Any],
    hyperparams: dict[str, Any] | None = None,
) -> LanguageAdapter:
    if torch is None:
        raise RuntimeError("PyTorch is required")
    md = (architecture or {}).get("metadata") or {}
    hp = hyperparams or {}
    model = _TinyDecoderLM(
        d_model=int(md.get("d_model", 256)),
        num_layers=int(md.get("num_layers", 4)),
        num_heads=int(md.get("num_heads", 4)),
        vocab=int(md.get("vocab_size", 256)),
    )
    opt = torch.optim.AdamW(
        model.parameters(),
        lr=float(hp.get("learning_rate", 3e-4)),
        betas=(0.9, 0.95),
    )
    log.info(
        "built language adapter (stub): %d params",
        sum(p.numel() for p in model.parameters()),
    )
    return LanguageAdapter(
        _model=model,
        _optimizer=opt,
        seq_len=int(hp.get("seq_len", 64)),
        batch_size=int(hp.get("batch_size", 4)),
    )


__all__ = ["LanguageAdapter", "build_adapter"]
