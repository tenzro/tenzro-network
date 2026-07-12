"""GRPO-style RL post-training inner loop.

Runs when ``TrainingTaskSpec.objective`` is ``RlPostTraining`` (see
``tenzro_types::training::TrainingObjective``). Per inner step the driver
takes one prompt from the shard, samples ``group_size`` rollouts from the
current policy, scores them with the sponsor-referenced reward callable,
computes group-relative advantages ``(r - mean) / (std + eps)``, and takes
one optimizer step on the clipped surrogate objective with a k3 KL penalty
against the sampling-time policy (Group Relative Policy Optimization — the
pattern used by prime-rl / TRL ``GRPOTrainer``; no value model, no frozen
reference copy).

The outer-gradient contract is unchanged: the loop returns the same
``(pre_state, post_state, InnerStepReport)`` triple as
:func:`tenzro_trainer.inner_loop.run_inner_loop`, so fragment partitioning,
quantization, Open-tier activation commitments, and submission all work
verbatim on the RL delta.
"""

from __future__ import annotations

import importlib
import logging
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Protocol, runtime_checkable

try:
    import torch
except ImportError:  # pragma: no cover
    torch = None  # type: ignore[assignment]

from tenzro_trainer.inner_loop import InnerStepReport, snapshot_state
from tenzro_trainer.types import RlConfig

log = logging.getLogger(__name__)

# Reward callable: (prompt, completion) -> scalar reward.
RewardFn = Callable[[str, str], float]

# Numerical floor on the group-reward std so a uniform group yields zero
# advantages instead of a division blow-up.
ADVANTAGE_STD_EPS = 1e-6


@dataclass
class Rollout:
    """One sampled completion plus its sampling-time per-token logprobs.

    ``old_logprobs`` are taken from the (temperature-scaled) policy
    distribution the tokens were actually drawn from, detached — they anchor
    both the surrogate ratio and the k3 KL penalty.
    """

    completion: str
    token_ids: list[int]
    old_logprobs: "torch.Tensor"  # [T], detached


@runtime_checkable
class RolloutAdapter(Protocol):
    """Modality-specific rollout interface for RL post-training.

    The language implementation lives in
    :mod:`tenzro_trainer.adapters.language`
    (``LanguageRolloutAdapter`` / ``build_rollout_adapter``).
    """

    def model(self) -> "torch.nn.Module": ...

    def optimizer(self) -> "torch.optim.Optimizer": ...

    def shard_prompts(self, shard_uri: str) -> Iterable[str]:
        """Yield prompts from the assigned shard (one rollout group each)."""
        ...

    def sample_rollouts(
        self,
        prompt: str,
        group_size: int,
        max_new_tokens: int,
        temperature: float,
    ) -> list[Rollout]:
        """Sample ``group_size`` completions from the current policy (no grad)."""
        ...

    def rollout_logprobs(
        self, prompt: str, rollout: Rollout, temperature: float
    ) -> "torch.Tensor":
        """Per-token logprobs of ``rollout`` under the current policy, with grad.

        Must use the same temperature scaling as sampling so the surrogate
        ratio is exactly 1 before the first optimizer step.
        """
        ...


def load_reward(reward_ref: str) -> RewardFn:
    """Resolve ``TrainingTaskSpec.objective.reward_ref`` to a callable.

    Format: ``py:<module.path>:<callable>``, e.g.
    ``py:my_rewards.math:score_completion``.
    """
    parts = reward_ref.split(":")
    if len(parts) != 3 or parts[0] != "py" or not parts[1] or not parts[2]:
        raise ValueError(
            f"reward_ref must be 'py:<module.path>:<callable>', got {reward_ref!r}"
        )
    module = importlib.import_module(parts[1])
    fn = getattr(module, parts[2], None)
    if not callable(fn):
        raise ValueError(
            f"reward_ref {reward_ref!r} does not resolve to a callable"
        )
    return fn


def group_advantages(rewards: list[float]) -> "torch.Tensor":
    """Group-relative advantages: ``(r - mean) / (std + eps)``.

    A group with identical rewards (std 0) yields all-zero advantages — no
    learning signal from that prompt, which is the correct GRPO behavior.
    """
    if torch is None:
        raise RuntimeError("PyTorch is required")
    r = torch.tensor(rewards, dtype=torch.float32)
    return (r - r.mean()) / (r.std(unbiased=False) + ADVANTAGE_STD_EPS)


def grpo_loss(
    new_logprobs: "torch.Tensor",
    old_logprobs: "torch.Tensor",
    advantage: "torch.Tensor",
    clip_epsilon: float,
    kl_coeff: float,
) -> "torch.Tensor":
    """Per-rollout clipped surrogate + k3 KL penalty.

    ``ratio = exp(new - old)`` per token; the surrogate is
    ``min(ratio * A, clamp(ratio, 1-eps, 1+eps) * A)`` averaged over tokens.
    The KL term is the k3 estimator ``exp(old - new) - (old - new) - 1``
    against the sampling-time policy, so drift within the inner window is
    penalized without holding a frozen reference model in memory.
    """
    if torch is None:
        raise RuntimeError("PyTorch is required")
    if new_logprobs.numel() == 0:
        raise ValueError("rollout has zero generated tokens")
    if new_logprobs.shape != old_logprobs.shape:
        raise ValueError(
            f"logprob shape mismatch: new {tuple(new_logprobs.shape)} vs "
            f"old {tuple(old_logprobs.shape)}"
        )
    ratio = torch.exp(new_logprobs - old_logprobs)
    unclipped = ratio * advantage
    clipped = torch.clamp(ratio, 1.0 - clip_epsilon, 1.0 + clip_epsilon) * advantage
    surrogate = torch.minimum(unclipped, clipped).mean()
    log_ratio = old_logprobs - new_logprobs
    kl = (torch.exp(log_ratio) - log_ratio - 1.0).mean()
    return -surrogate + kl_coeff * kl


def run_rl_inner_loop(
    adapter: RolloutAdapter,
    shard_uri: str,
    inner_steps: int,
    rl: RlConfig,
    reward_fn: RewardFn,
) -> tuple[dict[str, "torch.Tensor"], dict[str, "torch.Tensor"], InnerStepReport]:
    """Run ``inner_steps`` GRPO steps (one prompt group each) against ``shard_uri``.

    Returns ``(pre_state, post_state, report)`` — the same contract as the
    supervised :func:`tenzro_trainer.inner_loop.run_inner_loop`, with
    ``loss_trajectory`` carrying the per-step GRPO losses (the loss half of
    the Open-tier activation commitment) and ``samples_processed`` counting
    rollouts.
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
    rollouts_processed = 0
    prompt_iter = iter(adapter.shard_prompts(shard_uri))
    start = time.perf_counter()
    for step in range(inner_steps):
        try:
            prompt = next(prompt_iter)
        except StopIteration:
            log.warning(
                "prompt shard exhausted at step %d/%d (will reuse from start)",
                step,
                inner_steps,
            )
            prompt_iter = iter(adapter.shard_prompts(shard_uri))
            try:
                prompt = next(prompt_iter)
            except StopIteration:
                raise RuntimeError(
                    f"shard {shard_uri!r} produced zero prompts"
                ) from None

        rollouts = adapter.sample_rollouts(
            prompt, rl.group_size, rl.max_new_tokens, rl.temperature
        )
        if len(rollouts) != rl.group_size:
            raise RuntimeError(
                f"adapter returned {len(rollouts)} rollouts, expected "
                f"group_size={rl.group_size}"
            )
        rewards = [float(reward_fn(prompt, r.completion)) for r in rollouts]
        advantages = group_advantages(rewards)

        optimizer.zero_grad(set_to_none=True)
        per_rollout = []
        for rollout, advantage in zip(rollouts, advantages):
            new_lp = adapter.rollout_logprobs(prompt, rollout, rl.temperature)
            per_rollout.append(
                grpo_loss(
                    new_lp,
                    rollout.old_logprobs,
                    advantage,
                    rl.clip_epsilon,
                    rl.kl_coeff,
                )
            )
        loss = torch.stack(per_rollout).mean()
        loss.backward()
        optimizer.step()
        losses.append(float(loss.detach().item()))
        rollouts_processed += len(rollouts)
    wall_seconds = time.perf_counter() - start

    post_state = snapshot_state(model)
    report = InnerStepReport(
        steps_completed=inner_steps,
        final_loss=losses[-1] if losses else float("nan"),
        avg_loss=(sum(losses) / len(losses)) if losses else float("nan"),
        wall_seconds=wall_seconds,
        samples_processed=rollouts_processed,
        loss_trajectory=losses,
    )
    log.info(
        "RL inner loop: %d steps, %d rollouts in %.3fs → %.1f rollouts/s",
        report.steps_completed,
        report.samples_processed,
        report.wall_seconds,
        report.samples_per_second,
    )
    return pre_state, post_state, report


__all__ = [
    "ADVANTAGE_STD_EPS",
    "RewardFn",
    "Rollout",
    "RolloutAdapter",
    "group_advantages",
    "grpo_loss",
    "load_reward",
    "run_rl_inner_loop",
]
