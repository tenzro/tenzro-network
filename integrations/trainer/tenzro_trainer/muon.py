"""Muon inner optimizer + the inner-optimizer dispatcher for all adapters.

Muon (MomentUm Orthogonalized by Newton-Schulz; Keller Jordan et al.) runs
momentum SGD and then orthogonalizes each 2D weight update with a 5-step
Newton-Schulz iteration before applying it. As the inner optimizer under this
trainer's outer loop it converges with less communication than AdamW.

Matrix parameters (``ndim >= 2``, flattened to 2D for convs) take the Muon
path; 1D parameters (biases, norms) and embedding / output-head weights take
an in-optimizer AdamW fallback — orthogonalizing those hurts, per the Muon
reference implementation.

Selection is wire-driven: the task-spec ``metadata`` key ``inner_optimizer``
(``"muon"`` | ``"adamw"`` | ``"sgd"``, default ``"adamw"``) reaches every
adapter through :func:`build_inner_optimizer`.
"""

from __future__ import annotations

import logging
from typing import Any

try:
    import torch
    from torch import nn
except ImportError:  # pragma: no cover
    torch = None  # type: ignore[assignment]
    nn = None  # type: ignore[assignment]


log = logging.getLogger(__name__)


# Quintic Newton-Schulz coefficients from the Muon reference implementation —
# tuned to maximize slope at zero so small singular values are inflated fast.
_NS_COEFFS = (3.4445, -4.7750, 2.0315)


def zeropower_via_newtonschulz5(g: "torch.Tensor", steps: int = 5) -> "torch.Tensor":
    """Approximate ``U V^T`` for ``G = U S V^T`` via quintic Newton-Schulz.

    Runs in float32. The iteration does not converge singular values exactly
    to 1 — it lands them in a band around 1, which is what Muon wants (the
    slope-at-zero-maximizing tuning beats an exact orthogonalization).
    """
    if g.ndim != 2:
        raise ValueError(f"Newton-Schulz expects a 2D tensor, got ndim={g.ndim}")
    a, b, c = _NS_COEFFS
    x = g.to(torch.float32)
    transposed = x.size(0) > x.size(1)
    if transposed:
        x = x.mT
    x = x / (x.norm() + 1e-7)
    for _ in range(steps):
        gram = x @ x.mT
        x = a * x + (b * gram + c * gram @ gram) @ x
    if transposed:
        x = x.mT
    return x.to(g.dtype)


def partition_parameters(
    model: "nn.Module",
) -> tuple[list["torch.Tensor"], list["torch.Tensor"]]:
    """Split trainable parameters into ``(muon_params, fallback_params)``.

    Muon takes matrix-shaped weights (``ndim >= 2``; conv filters are
    flattened to 2D inside the step). Embeddings and output heads stay on the
    AdamW fallback per the Muon reference recipe — their rows act as lookup
    vectors, not linear maps, so orthogonalization is the wrong prior.
    """
    fallback_name_tags = ("embed", "lm_head", "wte", "wpe", "head")
    muon_params: list[torch.Tensor] = []
    fallback_params: list[torch.Tensor] = []
    for name, p in model.named_parameters():
        if not p.requires_grad:
            continue
        lowered = name.lower()
        if p.ndim >= 2 and not any(tag in lowered for tag in fallback_name_tags):
            muon_params.append(p)
        else:
            fallback_params.append(p)
    return muon_params, fallback_params


class Muon(torch.optim.Optimizer if torch is not None else object):  # type: ignore[misc]
    """Muon with an in-optimizer AdamW fallback.

    Construct with explicit param groups carrying a ``use_muon`` flag::

        Muon([
            {"params": muon_params, "use_muon": True, "lr": 0.02},
            {"params": other_params, "use_muon": False, "lr": 3e-4},
        ])

    Muon groups: momentum (optionally Nesterov) + Newton-Schulz
    orthogonalization + aspect-ratio-scaled update
    (``-lr * max(1, rows/cols)**0.5``). Fallback groups: standard decoupled
    AdamW with bias correction.
    """

    def __init__(
        self,
        params: Any,
        lr: float = 0.02,
        momentum: float = 0.95,
        nesterov: bool = True,
        ns_steps: int = 5,
        weight_decay: float = 0.0,
        adamw_betas: tuple[float, float] = (0.9, 0.95),
        adamw_eps: float = 1e-8,
    ):
        if torch is None:
            raise RuntimeError("PyTorch is required")
        defaults = dict(
            lr=lr,
            momentum=momentum,
            nesterov=nesterov,
            ns_steps=ns_steps,
            weight_decay=weight_decay,
            adamw_betas=adamw_betas,
            adamw_eps=adamw_eps,
            use_muon=True,
        )
        super().__init__(params, defaults)

    @torch.no_grad()
    def step(self, closure: Any = None) -> Any:  # noqa: D102
        loss = None
        if closure is not None:
            with torch.enable_grad():
                loss = closure()
        for group in self.param_groups:
            if group["use_muon"]:
                self._step_muon(group)
            else:
                self._step_adamw(group)
        return loss

    def _step_muon(self, group: dict[str, Any]) -> None:
        from tenzro_trainer.distributed import full_tensor, is_dtensor

        lr = group["lr"]
        momentum = group["momentum"]
        wd = group["weight_decay"]
        for p in group["params"]:
            if p.grad is None:
                continue
            g = p.grad
            state = self.state[p]
            if "momentum_buffer" not in state:
                state["momentum_buffer"] = torch.zeros_like(g)
            buf: torch.Tensor = state["momentum_buffer"]
            buf.lerp_(g, 1.0 - momentum)
            d = g.lerp(buf, momentum) if group["nesterov"] else buf
            # Newton-Schulz needs the full matrix. Under FSDP2 the gradient
            # is a sharded DTensor, so gather it first (collective — every
            # rank walks the same param order). Momentum stays sharded.
            d_full = full_tensor(d)
            # Flatten conv filters etc. to 2D for the orthogonalization.
            d2 = d_full if d_full.ndim == 2 else d_full.view(d_full.size(0), -1)
            u = zeropower_via_newtonschulz5(d2, steps=group["ns_steps"])
            if wd != 0.0:
                p.mul_(1.0 - lr * wd)
            scale = max(1.0, d2.size(0) / d2.size(1)) ** 0.5
            if is_dtensor(p):
                from torch.distributed.tensor import distribute_tensor

                update = distribute_tensor(
                    u.view(p.shape).to(p.dtype), p.device_mesh, p.placements
                )
                p.add_(update, alpha=-lr * scale)
            else:
                p.add_(u.view_as(p), alpha=-lr * scale)

    def _step_adamw(self, group: dict[str, Any]) -> None:
        lr = group["lr"]
        beta1, beta2 = group["adamw_betas"]
        eps = group["adamw_eps"]
        wd = group["weight_decay"]
        for p in group["params"]:
            if p.grad is None:
                continue
            g = p.grad
            state = self.state[p]
            if "step" not in state:
                state["step"] = 0
                state["exp_avg"] = torch.zeros_like(g)
                state["exp_avg_sq"] = torch.zeros_like(g)
            state["step"] += 1
            exp_avg: torch.Tensor = state["exp_avg"]
            exp_avg_sq: torch.Tensor = state["exp_avg_sq"]
            exp_avg.lerp_(g, 1.0 - beta1)
            exp_avg_sq.mul_(beta2).addcmul_(g, g, value=1.0 - beta2)
            bias1 = 1.0 - beta1 ** state["step"]
            bias2 = 1.0 - beta2 ** state["step"]
            denom = (exp_avg_sq / bias2).sqrt_().add_(eps)
            if wd != 0.0:
                p.mul_(1.0 - lr * wd)
            p.addcdiv_(exp_avg, denom, value=-lr / bias1)


def build_inner_optimizer(
    model: "nn.Module",
    arch_metadata: dict[str, Any] | None,
    hyperparams: dict[str, Any] | None,
    *,
    default_lr: float,
    default_weight_decay: float = 0.0,
) -> "torch.optim.Optimizer":
    """Construct the inner optimizer every adapter uses.

    ``inner_optimizer`` (``"muon"`` | ``"adamw"`` | ``"sgd"``) is read from
    hyperparams first (the task-spec ``metadata`` map is threaded through as
    hyperparams by the CLI run loop), then architecture metadata, defaulting
    to ``"adamw"`` — the historical adapter behavior.

    Muon-specific knobs: ``muon_lr`` (default 0.02) and ``momentum``
    (default 0.95); the AdamW fallback group inside Muon uses
    ``learning_rate``. SGD honors ``momentum`` (default 0.9, Nesterov).
    """
    if torch is None:
        raise RuntimeError("PyTorch is required")
    md = arch_metadata or {}
    hp = hyperparams or {}
    choice = str(hp.get("inner_optimizer") or md.get("inner_optimizer") or "adamw")
    choice = choice.lower()
    lr = float(hp.get("learning_rate", default_lr))
    wd = float(hp.get("weight_decay", default_weight_decay))

    if choice == "muon":
        muon_params, fallback_params = partition_parameters(model)
        if not muon_params:
            raise ValueError(
                "inner_optimizer=muon requires at least one matrix-shaped "
                "(ndim >= 2, non-embedding/head) parameter"
            )
        muon_lr = float(hp.get("muon_lr", md.get("muon_lr", 0.02)))
        momentum = float(hp.get("momentum", 0.95))
        groups: list[dict[str, Any]] = [
            {"params": muon_params, "use_muon": True, "lr": muon_lr}
        ]
        if fallback_params:
            groups.append({"params": fallback_params, "use_muon": False, "lr": lr})
        log.info(
            "inner optimizer: muon (%d muon params, %d adamw-fallback params, "
            "muon_lr=%g, fallback_lr=%g)",
            len(muon_params),
            len(fallback_params),
            muon_lr,
            lr,
        )
        return Muon(groups, momentum=momentum, weight_decay=wd)
    # Optimize only parameters that carry gradient. For a full fine-tune that
    # is every parameter (unchanged behavior); for a LoRA/QLoRA model the base
    # is frozen and only the adapter matrices are trainable, so the optimizer
    # never allocates moment buffers over the frozen base.
    trainable = [p for p in model.parameters() if p.requires_grad]
    if choice == "sgd":
        momentum = float(hp.get("momentum", 0.9))
        log.info("inner optimizer: sgd (lr=%g, momentum=%g)", lr, momentum)
        return torch.optim.SGD(
            trainable,
            lr=lr,
            momentum=momentum,
            nesterov=momentum > 0.0,
            weight_decay=wd,
        )
    if choice == "adamw":
        log.info("inner optimizer: adamw (lr=%g, weight_decay=%g)", lr, wd)
        return torch.optim.AdamW(
            trainable, lr=lr, weight_decay=wd, betas=(0.9, 0.95)
        )
    raise ValueError(
        f"unrecognized inner_optimizer {choice!r}; expected muon|adamw|sgd"
    )


__all__ = [
    "Muon",
    "build_inner_optimizer",
    "partition_parameters",
    "zeropower_via_newtonschulz5",
]
