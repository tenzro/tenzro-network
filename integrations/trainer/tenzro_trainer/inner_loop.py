"""Generic H-step inner SGD driver.

Each modality adapter (timeseries, language, vision) provides a
:class:`TrainerAdapter` that knows:

* how to load a model into ``state_dict`` form,
* how to load a shard into an iterable of training batches,
* how to compute a loss tensor for a batch,
* how to step the optimizer.

The driver itself is modality-agnostic: snapshot the starting state, run H
inner SGD steps, return the post-step state. The outer-gradient packaging
in :mod:`tenzro_trainer.gradient` then computes ``Δθ = θ⁽ᴴ⁾ − θ⁽⁰⁾`` and
serializes per fragment.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Iterable, Protocol, runtime_checkable

try:
    import torch
except ImportError:  # pragma: no cover
    torch = None  # type: ignore[assignment]


log = logging.getLogger(__name__)


@runtime_checkable
class TrainerAdapter(Protocol):
    """Modality-specific trainer interface.

    Implementations live in :mod:`tenzro_trainer.adapters`.
    """

    def model(self) -> "torch.nn.Module": ...

    def optimizer(self) -> "torch.optim.Optimizer": ...

    def shard_batches(self, shard_uri: str) -> Iterable[object]:
        """Yield training batches from the assigned shard.

        Batches are opaque to the driver; the adapter's ``compute_loss`` knows
        how to consume them.
        """
        ...

    def compute_loss(self, batch: object) -> "torch.Tensor": ...


@dataclass
class InnerStepReport:
    """Diagnostic record returned at the end of an inner loop."""

    steps_completed: int
    final_loss: float
    avg_loss: float


def snapshot_state(model: "torch.nn.Module") -> dict[str, "torch.Tensor"]:
    """Detached, CPU-residing copy of every parameter tensor.

    We CPU-copy so the snapshot doesn't pin GPU memory across the loop and
    isn't mutated when the optimizer steps the live parameters.
    """
    if torch is None:
        raise RuntimeError("PyTorch is required")
    return {
        name: p.detach().to("cpu").clone()
        for name, p in model.state_dict().items()
    }


def load_partial_state(
    model: "torch.nn.Module", partial: dict[str, "torch.Tensor"]
) -> None:
    """Copy the given tensors into the model's live parameters, in place.

    Keys must exist in the model's ``state_dict``. Used to reset synced
    fragments to the round's starting weights ``θ⁽⁰⁾`` before the outer
    update is (re-)applied.
    """
    if torch is None:
        raise RuntimeError("PyTorch is required")
    sd = model.state_dict()
    with torch.no_grad():
        for k, v in partial.items():
            if k not in sd:
                raise KeyError(f"state-dict key {k!r} not found in model")
            sd[k].copy_(v.to(sd[k].device, sd[k].dtype))


def apply_state_delta(
    model: "torch.nn.Module", delta: dict[str, "torch.Tensor"]
) -> None:
    """Add ``delta[k]`` to the model's live parameter ``k``, in place."""
    if torch is None:
        raise RuntimeError("PyTorch is required")
    sd = model.state_dict()
    with torch.no_grad():
        for k, d in delta.items():
            if k not in sd:
                raise KeyError(f"state-dict key {k!r} not found in model")
            sd[k].add_(d.to(sd[k].device, sd[k].dtype))


@dataclass
class OuterUpdateScheduler:
    """Applies outer updates immediately or with a one-round delay.

    DiLoCoX (arXiv 2506.21263) one-step-delayed apply: the aggregate computed
    at round ``r`` is applied at the *start* of round ``r + 1``, overlapping
    the outer synchronization with the next inner-step window. When
    ``delayed`` is ``False`` (the classic DiLoCo default), updates apply
    as soon as they arrive.
    """

    delayed: bool = False
    _pending: dict[str, "torch.Tensor"] | None = field(default=None, init=False)

    def on_round_start(self, model: "torch.nn.Module") -> None:
        """Apply any update buffered during the previous round."""
        if self._pending is not None:
            apply_state_delta(model, self._pending)
            self._pending = None

    def on_outer_update(
        self, model: "torch.nn.Module", delta: dict[str, "torch.Tensor"]
    ) -> None:
        """Route an outer update: apply now, or buffer for the next round."""
        if self.delayed:
            self._pending = delta
        else:
            apply_state_delta(model, delta)

    def flush(self, model: "torch.nn.Module") -> None:
        """Apply a still-buffered update at end of run so no delta is lost."""
        if self._pending is not None:
            apply_state_delta(model, self._pending)
            self._pending = None


def run_inner_loop(
    adapter: TrainerAdapter,
    shard_uri: str,
    inner_steps: int,
) -> tuple[dict[str, "torch.Tensor"], dict[str, "torch.Tensor"], InnerStepReport]:
    """Run ``inner_steps`` SGD steps against ``shard_uri``.

    Returns ``(pre_state, post_state, report)`` where both states are CPU
    copies suitable for ``compute_outer_delta``.
    """
    if torch is None:
        raise RuntimeError("PyTorch is required")
    if inner_steps <= 0:
        raise ValueError("inner_steps must be positive")

    model = adapter.model()
    optimizer = adapter.optimizer()
    pre_state = snapshot_state(model)

    model.train()
    losses: list[float] = []
    batch_iter = iter(adapter.shard_batches(shard_uri))
    for step in range(inner_steps):
        try:
            batch = next(batch_iter)
        except StopIteration:
            log.warning(
                "shard exhausted at step %d/%d (will reuse from start)",
                step,
                inner_steps,
            )
            batch_iter = iter(adapter.shard_batches(shard_uri))
            try:
                batch = next(batch_iter)
            except StopIteration:
                raise RuntimeError(
                    f"shard {shard_uri!r} produced zero batches"
                ) from None
        optimizer.zero_grad(set_to_none=True)
        loss = adapter.compute_loss(batch)
        loss.backward()
        optimizer.step()
        losses.append(float(loss.detach().item()))

    post_state = snapshot_state(model)
    report = InnerStepReport(
        steps_completed=inner_steps,
        final_loss=losses[-1] if losses else float("nan"),
        avg_loss=(sum(losses) / len(losses)) if losses else float("nan"),
    )
    return pre_state, post_state, report
