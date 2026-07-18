"""OuterUpdateScheduler + partial-state helpers (delayed apply)."""

from __future__ import annotations

import pytest

torch = pytest.importorskip("torch")
from torch import nn  # noqa: E402

from tenzro_trainer.inner_loop import (  # noqa: E402
    OuterUpdateScheduler,
    apply_state_delta,
    load_partial_state,
    snapshot_state,
)


def _model() -> "nn.Module":
    torch.manual_seed(0)
    return nn.Linear(3, 2)


def _delta(model: "nn.Module", value: float) -> dict:
    return {k: torch.full_like(v, value) for k, v in model.state_dict().items()}


def test_load_partial_state_copies_and_rejects_unknown_keys():
    model = _model()
    snap = snapshot_state(model)
    with torch.no_grad():
        model.weight.add_(1.0)
    load_partial_state(model, {"weight": snap["weight"]})
    assert torch.equal(model.state_dict()["weight"], snap["weight"])
    with pytest.raises(KeyError):
        load_partial_state(model, {"nope": snap["weight"]})


def test_apply_state_delta_adds_in_place_and_rejects_unknown_keys():
    model = _model()
    before = snapshot_state(model)
    apply_state_delta(model, _delta(model, 0.5))
    after = model.state_dict()
    for k in before:
        assert torch.allclose(after[k], before[k] + 0.5)
    with pytest.raises(KeyError):
        apply_state_delta(model, {"nope": before["weight"]})


def test_immediate_scheduler_applies_on_arrival():
    model = _model()
    before = snapshot_state(model)
    sched = OuterUpdateScheduler(delayed=False)
    sched.on_round_start(model)  # no-op with nothing pending
    sched.on_outer_update(model, _delta(model, 1.0))
    assert torch.allclose(model.state_dict()["bias"], before["bias"] + 1.0)
    sched.flush(model)  # nothing pending → no double-apply
    assert torch.allclose(model.state_dict()["bias"], before["bias"] + 1.0)


def test_delayed_scheduler_applies_at_next_round_start():
    model = _model()
    before = snapshot_state(model)
    sched = OuterUpdateScheduler(delayed=True)
    sched.on_outer_update(model, _delta(model, 1.0))
    # Buffered — model untouched.
    assert torch.equal(model.state_dict()["bias"], before["bias"])
    sched.on_round_start(model)
    assert torch.allclose(model.state_dict()["bias"], before["bias"] + 1.0)
    # Buffer cleared — second round start does not re-apply.
    sched.on_round_start(model)
    assert torch.allclose(model.state_dict()["bias"], before["bias"] + 1.0)


def test_delayed_scheduler_flush_applies_final_pending_delta():
    model = _model()
    before = snapshot_state(model)
    sched = OuterUpdateScheduler(delayed=True)
    sched.on_outer_update(model, _delta(model, 0.25))
    sched.flush(model)
    assert torch.allclose(model.state_dict()["bias"], before["bias"] + 0.25)
    sched.flush(model)  # idempotent
    assert torch.allclose(model.state_dict()["bias"], before["bias"] + 0.25)
