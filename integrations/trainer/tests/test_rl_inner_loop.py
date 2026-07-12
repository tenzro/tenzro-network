"""GRPO RL post-training inner loop (tenzro_trainer.rl)."""

from __future__ import annotations

import pytest

torch = pytest.importorskip("torch")
from torch import nn  # noqa: E402

from tenzro_trainer.gradient import compute_outer_delta  # noqa: E402
from tenzro_trainer.rl import (  # noqa: E402
    Rollout,
    RolloutAdapter,
    group_advantages,
    grpo_loss,
    load_reward,
    run_rl_inner_loop,
)
from tenzro_trainer.types import RlConfig  # noqa: E402

VOCAB = 5


class _BanditPolicy(nn.Module):
    """Context-free categorical policy over a tiny vocabulary."""

    def __init__(self) -> None:
        super().__init__()
        self.logits = nn.Parameter(torch.zeros(VOCAB))


class _SyntheticAdapter:
    """Minimal RolloutAdapter: samples from the bandit policy.

    Completions are wire-encoded as comma-joined token ids so the reward
    callable can score them without a tokenizer.
    """

    def __init__(self, prompts: list[str], tokens_per_rollout: int = 6) -> None:
        torch.manual_seed(0)
        self._prompts = prompts
        self._tokens = tokens_per_rollout
        self._model = _BanditPolicy()
        self._optimizer = torch.optim.SGD(self._model.parameters(), lr=0.5)

    def model(self) -> nn.Module:
        return self._model

    def optimizer(self) -> torch.optim.Optimizer:
        return self._optimizer

    def shard_prompts(self, shard_uri: str):
        return list(self._prompts)

    def _logprobs(self, temperature: float) -> torch.Tensor:
        return torch.log_softmax(self._model.logits / temperature, dim=-1)

    def sample_rollouts(self, prompt, group_size, max_new_tokens, temperature):
        n = min(self._tokens, max_new_tokens)
        out = []
        with torch.no_grad():
            lp = self._logprobs(temperature)
            for _ in range(group_size):
                ids = torch.multinomial(lp.exp(), n, replacement=True)
                out.append(
                    Rollout(
                        completion=",".join(str(int(i)) for i in ids),
                        token_ids=[int(i) for i in ids],
                        old_logprobs=lp[ids].detach(),
                    )
                )
        return out

    def rollout_logprobs(self, prompt, rollout, temperature):
        lp = self._logprobs(temperature)
        return lp[torch.tensor(rollout.token_ids)]


def _reward_prefers_token_zero(prompt: str, completion: str) -> float:
    ids = [int(t) for t in completion.split(",") if t]
    return sum(1.0 for i in ids if i == 0) / max(len(ids), 1)


def _rl(group_size: int = 4) -> RlConfig:
    return RlConfig(
        group_size=group_size,
        kl_coeff=0.01,
        clip_epsilon=0.2,
        max_new_tokens=8,
        temperature=1.0,
        reward_ref="py:tests.test_rl_inner_loop:_reward_prefers_token_zero",
    )


def test_synthetic_adapter_satisfies_protocol():
    assert isinstance(_SyntheticAdapter(["p"]), RolloutAdapter)


def test_load_reward_resolves_and_rejects():
    fn = load_reward("py:tests.test_rl_inner_loop:_reward_prefers_token_zero")
    assert fn("q", "0,0,1,2") == 0.5
    for bad in (
        "my_rewards.math:score",  # missing py: prefix
        "py:my_rewards.math",  # missing callable
        "py::score",  # empty module
        "py:math:",  # empty callable
    ):
        with pytest.raises(ValueError):
            load_reward(bad)
    with pytest.raises(ValueError):
        load_reward("py:math:pi")  # resolves but not callable


def test_group_advantages_normalizes_and_zeroes_uniform_groups():
    a = group_advantages([1.0, 0.0, 1.0, 0.0])
    assert torch.allclose(a.mean(), torch.tensor(0.0), atol=1e-6)
    assert a[0] > 0 > a[1]
    uniform = group_advantages([0.7, 0.7, 0.7])
    assert torch.allclose(uniform, torch.zeros(3), atol=1e-5)


def test_grpo_loss_identity_ratio_and_guards():
    lp = torch.log(torch.tensor([0.25, 0.5, 0.125]))
    # new == old → ratio 1, KL 0 → loss = -advantage.
    loss = grpo_loss(lp, lp.clone(), torch.tensor(2.0), 0.2, 0.1)
    assert torch.allclose(loss, torch.tensor(-2.0), atol=1e-6)
    with pytest.raises(ValueError):
        grpo_loss(torch.empty(0), torch.empty(0), torch.tensor(1.0), 0.2, 0.1)
    with pytest.raises(ValueError):
        grpo_loss(lp, lp[:2], torch.tensor(1.0), 0.2, 0.1)


def test_run_rl_inner_loop_learns_and_reports():
    adapter = _SyntheticAdapter(["what is 2+2?", "name a prime"])
    reward_fn = load_reward(_rl().reward_ref)
    steps = 20
    pre, post, report = run_rl_inner_loop(
        adapter, "file:///unused", steps, _rl(), reward_fn
    )
    assert report.steps_completed == steps
    assert len(report.loss_trajectory) == steps
    assert report.samples_processed == steps * _rl().group_size
    delta = compute_outer_delta(pre, post)
    assert any(v.abs().sum() > 0 for v in delta.values())
    # The reward prefers token 0 — its logit must have risen above the rest.
    logits = adapter.model().logits.detach()
    assert logits[0] > logits[1:].max()


def test_run_rl_inner_loop_reuses_exhausted_prompt_shard():
    adapter = _SyntheticAdapter(["only prompt"])
    reward_fn = load_reward(_rl().reward_ref)
    _, _, report = run_rl_inner_loop(adapter, "x", 3, _rl(), reward_fn)
    assert report.steps_completed == 3


def test_run_rl_inner_loop_rejects_empty_shard_and_bad_group():
    empty = _SyntheticAdapter([])
    reward_fn = _reward_prefers_token_zero
    with pytest.raises(RuntimeError, match="zero prompts"):
        run_rl_inner_loop(empty, "x", 1, _rl(), reward_fn)

    class _ShortGroup(_SyntheticAdapter):
        def sample_rollouts(self, prompt, group_size, max_new_tokens, temperature):
            return super().sample_rollouts(
                prompt, group_size - 1, max_new_tokens, temperature
            )

    with pytest.raises(RuntimeError, match="expected"):
        run_rl_inner_loop(_ShortGroup(["p"]), "x", 1, _rl(), reward_fn)

    with pytest.raises(ValueError, match="inner_steps"):
        run_rl_inner_loop(_SyntheticAdapter(["p"]), "x", 0, _rl(), reward_fn)
