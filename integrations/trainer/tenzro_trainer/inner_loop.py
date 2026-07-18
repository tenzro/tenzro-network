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
import time
from dataclasses import dataclass, field
from typing import Iterable, Protocol, runtime_checkable

try:
    import torch
except ImportError:  # pragma: no cover
    torch = None  # type: ignore[assignment]


from tenzro_trainer.distributed import add_into, copy_into, full_tensor

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
    """Diagnostic record returned at the end of an inner loop.

    ``wall_seconds`` is the time spent in the H forward/backward/step
    iterations only (model construction and shard load are excluded).
    ``samples_processed`` is the sum of the leading batch dimension across
    all steps. ``samples_per_second`` and ``steps_per_second`` are derived
    from those two so an operator can quote a single defensible throughput
    figure per hardware class.
    """

    steps_completed: int
    final_loss: float
    avg_loss: float
    wall_seconds: float = 0.0
    samples_processed: int = 0
    # Per-inner-step losses in step order — the loss half of the Open-tier
    # activation commitment (gradient.build_activation_commitment).
    loss_trajectory: list[float] = field(default_factory=list)

    @property
    def samples_per_second(self) -> float:
        return self.samples_processed / self.wall_seconds if self.wall_seconds > 0 else float("nan")

    @property
    def steps_per_second(self) -> float:
        return self.steps_completed / self.wall_seconds if self.wall_seconds > 0 else float("nan")


def _batch_sample_count(batch: object) -> int:
    """Best-effort count of training samples in one batch.

    Adapters yield opaque batches. The convention across the reference
    adapters is that the first tensor's leading dimension is the sample
    (mini-batch) axis: a bare tensor ``[B, ...]``, or a tuple/list whose
    first element is the input tensor ``[B, ...]``. Anything the driver
    can't interpret counts as a single sample so throughput stays finite.
    """
    t = batch
    if isinstance(batch, (tuple, list)) and batch:
        t = batch[0]
    shape = getattr(t, "shape", None)
    if shape is not None and len(shape) >= 1:
        return int(shape[0])
    return 1


def trainable_param_names(model: "torch.nn.Module") -> set[str]:
    """Names of parameters that carry gradient this step (``requires_grad``).

    For a full fine-tune every parameter is trainable, so this is the whole
    parameter set. For a LoRA/QLoRA model the base is frozen and only the
    low-rank adapter matrices (and, under alternating aggregation, only the
    round's active factor) are trainable — so the returned set is exactly the
    tensors whose delta is meaningful to transmit.
    """
    if torch is None:
        raise RuntimeError("PyTorch is required")
    return {name for name, p in model.named_parameters() if p.requires_grad}


def snapshot_state(model: "torch.nn.Module") -> dict[str, "torch.Tensor"]:
    """Detached, CPU-residing copy of the trainable parameter tensors.

    We CPU-copy so the snapshot doesn't pin GPU memory across the loop and
    isn't mutated when the optimizer steps the live parameters.

    Only ``requires_grad`` parameters are snapshotted. For a full fine-tune
    that is every parameter (unchanged behavior); for LoRA/QLoRA it is just
    the adapter matrices, so ``Δθ = θ⁽ᴴ⁾ − θ⁽⁰⁾`` and the fragment partition
    that follows carry adapter deltas only — never zero-deltas over a frozen
    base. Buffers (non-parameter state-dict entries such as RoPE caches) are
    excluded because they are not trained.

    Under FSDP2 the parameters are DTensors; each is gathered to its full
    (unsharded) value first. That gather is a collective, so every rank must
    call this function at the same points in the round — which the driver
    guarantees by snapshotting on all ranks.
    """
    if torch is None:
        raise RuntimeError("PyTorch is required")
    trainable = trainable_param_names(model)
    return {
        name: full_tensor(p.detach()).to("cpu").clone()
        for name, p in model.named_parameters()
        if name in trainable
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
            copy_into(sd[k], v)


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
            add_into(sd[k], d)


@dataclass
class OuterUpdateScheduler:
    """Applies outer updates immediately or with a one-round delay.

    One-step-delayed apply: the aggregate computed at round ``r`` is applied
    at the *start* of round ``r + 1``, overlapping the outer synchronization
    with the next inner-step window. When ``delayed`` is ``False`` (the
    default), updates apply as soon as they arrive.
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
    samples_processed = 0
    batch_iter = iter(adapter.shard_batches(shard_uri))
    start = time.perf_counter()
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
        samples_processed += _batch_sample_count(batch)
    wall_seconds = time.perf_counter() - start

    post_state = snapshot_state(model)
    report = InnerStepReport(
        steps_completed=inner_steps,
        final_loss=losses[-1] if losses else float("nan"),
        avg_loss=(sum(losses) / len(losses)) if losses else float("nan"),
        wall_seconds=wall_seconds,
        samples_processed=samples_processed,
        loss_trajectory=losses,
    )
    log.info(
        "inner loop: %d steps, %d samples in %.3fs → %.1f samples/s, %.2f steps/s",
        report.steps_completed,
        report.samples_processed,
        report.wall_seconds,
        report.samples_per_second,
        report.steps_per_second,
    )
    return pre_state, post_state, report
