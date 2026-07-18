"""Multi-process training context and FSDP2 sharding.

Provides the process-group lifecycle for torchrun-launched trainers, the
FSDP2 (``torch.distributed.fsdp.fully_shard``) sharding entry point used by
the language adapter, and DTensor-aware tensor helpers consumed by the inner
loop and the Muon optimizer.

Single-process runs (no torchrun) are the default: ``DistContext.detect()``
returns a disabled context and every helper degrades to a plain-tensor
no-op, so nothing in this module requires a GPU or a process group to
import or exercise.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict

try:
    import torch
    import torch.nn as nn
except ImportError:  # pragma: no cover
    torch = None  # type: ignore[assignment]
    nn = None  # type: ignore[assignment]


@dataclass(frozen=True)
class DistContext:
    """Process-group coordinates for one trainer process."""

    enabled: bool
    rank: int
    world_size: int
    local_rank: int

    @property
    def is_primary(self) -> bool:
        return self.rank == 0

    @staticmethod
    def detect() -> "DistContext":
        """Read torchrun environment variables and initialize the group.

        Returns a disabled context when RANK/WORLD_SIZE are absent or the
        world size is 1. Initialization is idempotent: an already-initialized
        default group is reused.
        """
        rank = int(os.environ.get("RANK", "-1"))
        world_size = int(os.environ.get("WORLD_SIZE", "1"))
        local_rank = int(os.environ.get("LOCAL_RANK", "0"))
        if rank < 0 or world_size <= 1:
            return DistContext(enabled=False, rank=0, world_size=1, local_rank=0)
        if torch is None:
            raise RuntimeError("PyTorch is required for multi-process training")

        import torch.distributed as dist

        if not dist.is_initialized():
            backend = "nccl" if torch.cuda.is_available() else "gloo"
            if backend == "nccl":
                torch.cuda.set_device(local_rank)
            dist.init_process_group(backend=backend)
        return DistContext(
            enabled=True, rank=rank, world_size=world_size, local_rank=local_rank
        )


def shard_model_fsdp2(model: nn.Module, ctx: DistContext) -> nn.Module:
    """Apply FSDP2 per-parameter sharding to a transformer language model.

    Shards each block of the largest ``nn.ModuleList`` (the decoder stack)
    individually so prefetch overlaps compute, then shards the root module
    for everything outside the stack. Parameters are held in bf16 for
    compute with fp32 gradient reduction, matching the reference
    configuration.

    Must run before the optimizer is constructed — FSDP2 swaps parameters
    for DTensors and the optimizer has to see the swapped handles.
    """
    if not ctx.enabled:
        return model

    from torch.distributed.fsdp import MixedPrecisionPolicy, fully_shard

    mp = MixedPrecisionPolicy(
        param_dtype=torch.bfloat16, reduce_dtype=torch.float32
    )

    stack: nn.ModuleList | None = None
    for module in model.modules():
        if isinstance(module, nn.ModuleList) and (
            stack is None or len(module) > len(stack)
        ):
            stack = module
    if stack is not None:
        for block in stack:
            fully_shard(block, mp_policy=mp)
    fully_shard(model, mp_policy=mp)
    return model


def is_dtensor(t: "torch.Tensor") -> bool:
    if torch is None:
        return False
    try:
        from torch.distributed.tensor import DTensor
    except ImportError:
        return False
    return isinstance(t, DTensor)


def full_tensor(t: torch.Tensor) -> torch.Tensor:
    """Materialize the unsharded value of a (possibly distributed) tensor.

    Collective when ``t`` is a DTensor — every rank must call it for the
    same parameter in the same order.
    """
    if is_dtensor(t):
        return t.full_tensor()
    return t


def copy_into(param: torch.Tensor, value: torch.Tensor) -> None:
    """Copy a full (replicated) tensor into a possibly sharded parameter."""
    if is_dtensor(param):
        from torch.distributed.tensor import distribute_tensor

        src = distribute_tensor(
            value.to(dtype=param.dtype), param.device_mesh, param.placements
        )
        param.copy_(src)
    else:
        param.copy_(value.to(device=param.device, dtype=param.dtype))


def add_into(param: torch.Tensor, delta: torch.Tensor) -> None:
    """Add a full (replicated) delta into a possibly sharded parameter."""
    if is_dtensor(param):
        from torch.distributed.tensor import distribute_tensor

        src = distribute_tensor(
            delta.to(dtype=param.dtype), param.device_mesh, param.placements
        )
        param.add_(src)
    else:
        param.add_(delta.to(device=param.device, dtype=param.dtype))


def context_metadata(ctx: DistContext) -> Dict[str, Any]:
    """Round-report metadata describing the process-group shape."""
    return {
        "dist_enabled": ctx.enabled,
        "dist_rank": ctx.rank,
        "dist_world_size": ctx.world_size,
    }
