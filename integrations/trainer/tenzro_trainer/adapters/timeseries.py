"""Timeseries trainer adapter (Phase 1 lead modality).

Targets TimesFM-class 200M-parameter decoder-only forecasters.

Phase 1 provides a *minimal in-process* adapter: a small Transformer decoder
that operates on patch embeddings of a univariate series, plus a parquet shard
loader. This is enough to exercise the whole decoupled outer-aggregation loop
in CI without needing 100 GB of pretraining data; production deployments
would override ``build_adapter`` with the upstream TimesFM (or Chronos /
Moirai) implementation while keeping the same :class:`TrainerAdapter` surface.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from typing import Any, Iterable

try:
    import torch
    from torch import nn
except ImportError:  # pragma: no cover
    torch = None  # type: ignore[assignment]
    nn = None  # type: ignore[assignment]


from tenzro_trainer.muon import build_inner_optimizer
from tenzro_trainer.shards import resolve_shard

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Reference model
# ---------------------------------------------------------------------------


class _TimeSeriesPatchTransformer(nn.Module if nn is not None else object):  # type: ignore[misc]
    """Decoder-only transformer over patch tokens of a univariate series.

    Patch size, context length, and horizon match the TimesFM convention
    (patch_size=32 by default). Stripped down for in-process training during
    Phase 1; the production adapter will swap in the real backbone.
    """

    def __init__(
        self,
        d_model: int = 256,
        num_layers: int = 4,
        num_heads: int = 4,
        patch_size: int = 32,
        max_patches: int = 64,
    ):
        super().__init__()
        self.patch_size = patch_size
        self.proj_in = nn.Linear(patch_size, d_model)
        self.pos = nn.Parameter(torch.zeros(max_patches, d_model))
        nn.init.trunc_normal_(self.pos, std=0.02)
        layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=num_heads,
            dim_feedforward=d_model * 4,
            batch_first=True,
            activation="gelu",
        )
        self.encoder = nn.TransformerEncoder(layer, num_layers=num_layers)
        self.proj_out = nn.Linear(d_model, patch_size)

    def forward(self, x_patches: "torch.Tensor") -> "torch.Tensor":  # noqa: D401
        # x_patches: [B, P, patch_size]
        b, p, _ = x_patches.shape
        h = self.proj_in(x_patches) + self.pos[:p].unsqueeze(0)
        causal_mask = nn.Transformer.generate_square_subsequent_mask(p).to(h.device)
        h = self.encoder(h, mask=causal_mask)
        return self.proj_out(h)


# ---------------------------------------------------------------------------
# Shard loader
# ---------------------------------------------------------------------------


def _load_parquet_series(uri: str) -> "torch.Tensor":
    """Load a univariate series from a parquet shard URI.

    ``tenzro://`` shards fetch from the local node's iroh blob store;
    ``ipfs://`` / ``ar://`` / ``http(s)://`` resolve through gateways.
    ``file://`` and bare paths pass through. See
    :func:`tenzro_trainer.shards.resolve_shard`.
    """
    if torch is None:
        raise RuntimeError("PyTorch is required")
    try:
        import pandas as pd
    except ImportError as e:  # pragma: no cover
        raise RuntimeError(
            "pandas is required for timeseries shards (pip install 'tenzro-trainer[timeseries]')"
        ) from e

    path = resolve_shard(uri)
    df = pd.read_parquet(path)
    if "value" not in df.columns:
        raise ValueError(f"parquet shard {path!r} must have a 'value' column")
    series = torch.tensor(df["value"].to_numpy(), dtype=torch.float32)
    return series


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


@dataclass
class TimeseriesAdapter:
    """Concrete :class:`TrainerAdapter` for the timeseries reference model."""

    _model: "_TimeSeriesPatchTransformer"
    _optimizer: "torch.optim.Optimizer"
    patch_size: int = 32
    context_patches: int = 16
    horizon_patches: int = 4
    batch_size: int = 8

    def model(self) -> "torch.nn.Module":
        return self._model

    def optimizer(self) -> "torch.optim.Optimizer":
        return self._optimizer

    def shard_batches(self, shard_uri: str) -> Iterable[object]:
        if torch is None:
            raise RuntimeError("PyTorch is required")
        series = _load_parquet_series(shard_uri)
        # Build patches.
        usable = (series.numel() // self.patch_size) * self.patch_size
        patches = series[:usable].reshape(-1, self.patch_size)
        ctx = self.context_patches
        hor = self.horizon_patches
        total = patches.shape[0] - ctx - hor
        if total <= 0:
            raise ValueError(
                f"shard {shard_uri!r} too short: need ≥ {ctx + hor} patches "
                f"of size {self.patch_size}, got {patches.shape[0]}"
            )
        # Yield random mini-batches indefinitely.
        rng = torch.Generator()
        rng.manual_seed(0)
        while True:
            idx = torch.randint(
                0, total, (self.batch_size,), generator=rng
            )
            ctx_batch = torch.stack([patches[i : i + ctx] for i in idx], dim=0)
            tgt_batch = torch.stack(
                [patches[i + 1 : i + 1 + ctx] for i in idx], dim=0
            )
            yield ctx_batch, tgt_batch

    def compute_loss(self, batch: object) -> "torch.Tensor":
        if torch is None:
            raise RuntimeError("PyTorch is required")
        ctx_batch, tgt_batch = batch  # type: ignore[misc]
        pred = self._model(ctx_batch)
        return torch.nn.functional.mse_loss(pred, tgt_batch)


def build_adapter(
    architecture: dict[str, Any],
    hyperparams: dict[str, Any] | None = None,
) -> TimeseriesAdapter:
    """Construct a :class:`TimeseriesAdapter` from architecture metadata.

    Honors the following keys in ``architecture.metadata`` (all optional):

    * ``d_model`` (default 256)
    * ``num_layers`` (default 4)
    * ``num_heads`` (default 4)
    * ``patch_size`` (default 32)
    * ``max_patches`` (default 64)

    Hyperparams override training-time choices: ``learning_rate`` (default 1e-4),
    ``batch_size`` (default 8), ``context_patches`` (default 16),
    ``horizon_patches`` (default 4). The inner optimizer is selected by
    ``inner_optimizer`` (``muon`` | ``adamw`` | ``sgd``) via
    :func:`tenzro_trainer.muon.build_inner_optimizer`.
    """
    if torch is None:
        raise RuntimeError("PyTorch is required")
    md = (architecture or {}).get("metadata") or {}
    hp = hyperparams or {}
    model = _TimeSeriesPatchTransformer(
        d_model=int(md.get("d_model", 256)),
        num_layers=int(md.get("num_layers", 4)),
        num_heads=int(md.get("num_heads", 4)),
        patch_size=int(md.get("patch_size", 32)),
        max_patches=int(md.get("max_patches", 64)),
    )
    opt = build_inner_optimizer(model, md, hp, default_lr=1e-4)
    log.info(
        "built timeseries adapter: %d params",
        sum(p.numel() for p in model.parameters()),
    )
    return TimeseriesAdapter(
        _model=model,
        _optimizer=opt,
        patch_size=int(md.get("patch_size", 32)),
        context_patches=int(hp.get("context_patches", 16)),
        horizon_patches=int(hp.get("horizon_patches", 4)),
        batch_size=int(hp.get("batch_size", 8)),
    )


__all__ = ["TimeseriesAdapter", "build_adapter"]


# Quiet a pyflakes/ruff complaint about unused math when env lacks torch.
_ = math
