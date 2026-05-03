"""Vision trainer adapter (Phase 1 stub).

A small ViT-style classifier for end-to-end loop tests. Production
deployments should override :func:`build_adapter` with a real ViT-L/14 or
ConvNeXt backbone, with shards exposed as image-tensor archives.
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


class _TinyViT(nn.Module if nn is not None else object):  # type: ignore[misc]
    """Patch-embedded ViT for tiny RGB inputs (32×32)."""

    def __init__(
        self,
        img_size: int = 32,
        patch: int = 4,
        d_model: int = 192,
        num_layers: int = 4,
        num_heads: int = 4,
        num_classes: int = 10,
    ):
        super().__init__()
        if img_size % patch != 0:
            raise ValueError("img_size must be divisible by patch")
        self.patch = patch
        self.proj = nn.Conv2d(3, d_model, kernel_size=patch, stride=patch)
        n_tokens = (img_size // patch) ** 2 + 1
        self.cls = nn.Parameter(torch.zeros(1, 1, d_model))
        self.pos = nn.Parameter(torch.zeros(1, n_tokens, d_model))
        nn.init.trunc_normal_(self.pos, std=0.02)
        layer = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=num_heads, batch_first=True, activation="gelu"
        )
        self.blocks = nn.TransformerEncoder(layer, num_layers=num_layers)
        self.head = nn.Linear(d_model, num_classes)

    def forward(self, imgs: "torch.Tensor") -> "torch.Tensor":
        x = self.proj(imgs).flatten(2).transpose(1, 2)
        b = x.shape[0]
        x = torch.cat([self.cls.expand(b, -1, -1), x], dim=1) + self.pos
        x = self.blocks(x)
        return self.head(x[:, 0])


@dataclass
class VisionAdapter:
    _model: "_TinyViT"
    _optimizer: "torch.optim.Optimizer"
    img_size: int = 32
    batch_size: int = 8
    num_classes: int = 10

    def model(self) -> "torch.nn.Module":
        return self._model

    def optimizer(self) -> "torch.optim.Optimizer":
        return self._optimizer

    def shard_batches(self, shard_uri: str) -> Iterable[object]:
        # In-memory synthetic batches keyed off a stable shard hash.
        if torch is None:
            raise RuntimeError("PyTorch is required")
        if not shard_uri.startswith(("file://", "synth://")):
            raise NotImplementedError(
                f"vision adapter only supports synth:// or file:// in Phase 1: {shard_uri}"
            )
        rng = torch.Generator()
        rng.manual_seed(abs(hash(shard_uri)) % (2**32))
        while True:
            x = torch.randn(
                self.batch_size, 3, self.img_size, self.img_size, generator=rng
            )
            y = torch.randint(0, self.num_classes, (self.batch_size,), generator=rng)
            yield x, y

    def compute_loss(self, batch: object) -> "torch.Tensor":
        if torch is None:
            raise RuntimeError("PyTorch is required")
        x, y = batch  # type: ignore[misc]
        logits = self._model(x)
        return torch.nn.functional.cross_entropy(logits, y)


def build_adapter(
    architecture: dict[str, Any],
    hyperparams: dict[str, Any] | None = None,
) -> VisionAdapter:
    if torch is None:
        raise RuntimeError("PyTorch is required")
    md = (architecture or {}).get("metadata") or {}
    hp = hyperparams or {}
    model = _TinyViT(
        img_size=int(md.get("img_size", 32)),
        patch=int(md.get("patch", 4)),
        d_model=int(md.get("d_model", 192)),
        num_layers=int(md.get("num_layers", 4)),
        num_heads=int(md.get("num_heads", 4)),
        num_classes=int(md.get("num_classes", 10)),
    )
    opt = torch.optim.AdamW(
        model.parameters(),
        lr=float(hp.get("learning_rate", 3e-4)),
        betas=(0.9, 0.95),
    )
    log.info(
        "built vision adapter (stub): %d params",
        sum(p.numel() for p in model.parameters()),
    )
    return VisionAdapter(
        _model=model,
        _optimizer=opt,
        img_size=int(md.get("img_size", 32)),
        batch_size=int(hp.get("batch_size", 8)),
        num_classes=int(md.get("num_classes", 10)),
    )


__all__ = ["VisionAdapter", "build_adapter"]
