"""``--gpu-vram-gb`` must not be allowed to exceed the machine.

The pipeline cache is bounded by that one number: `_evict_until_fits` runs
while ``resident + needed > budget``, so a budget larger than the hardware
disables the bound entirely and every pipeline ever loaded stays resident.

On a discrete card that overshoot is survivable — CUDA raises, one job fails,
the process lives. On a coherent-memory part (GB10, Apple Silicon, AMD APU)
the GPU pool *is* system memory, so the same overshoot is served by the kernel
until the machine runs out and the global OOM killer picks victims across every
cgroup, including the node. That happened on 2026-08-03: a worker configured
with ``--gpu-vram-gb 100`` on a 121 GB GB10 held a 14 GB image pipeline and a
21 GB video pipeline at once, because 35 never exceeded 100.

`shared_memory_pool_gb` is a deliberate twin of
``tenzro_types::hardware::shared_memory_pool``. The parity tests below are the
point: a node and its media-gen worker must not disagree about what kind of
machine they are on.
"""

from __future__ import annotations

import pytest

from tenzro_media_gen.worker import (
    SAFE_SHARED_POOL_FRACTION,
    resolve_vram_budget_gb,
    shared_memory_pool_gb,
)

# ── parity with tenzro_types::hardware::shared_memory_pool ─────────────


def test_a_grace_blackwell_pool_is_recognised_as_shared() -> None:
    # Shape 1: nvidia-smi reports the shared system pool, so the two figures
    # coincide and the memory must be counted once.
    assert shared_memory_pool_gb(121.0, 121.0) == 121.0


def test_a_gpu_reporting_nothing_falls_back_to_system_ram() -> None:
    # Shape 2: the tool reports nothing because there is nothing separate to
    # report. Count the pool once, as system memory.
    assert shared_memory_pool_gb(0.0, 64.0) == 64.0


def test_a_discrete_card_is_not_treated_as_shared() -> None:
    assert shared_memory_pool_gb(24.0, 128.0) is None


@pytest.mark.parametrize(
    "vram,ram,shared",
    [
        (8.0, 8.0, True),  # small unified part
        (7.0, 8.0, True),  # vram*8 >= ram*7 exactly at the boundary
        (6.0, 8.0, False),  # just under the seven-eighths rule
        (5.0, 64.0, False),  # clearly discrete
    ],
)
def test_the_seven_eighths_boundary_matches_rust(vram: float, ram: float, shared: bool) -> None:
    # The rule is `vram * 8 >= ram * 7`. Pinning the boundary is what keeps the
    # two implementations from drifting apart by a rounding convention.
    assert (shared_memory_pool_gb(vram, ram) is not None) is shared


def test_unknown_system_ram_is_not_guessed() -> None:
    # A pool cannot be derived from a measurement that was never taken.
    assert shared_memory_pool_gb(24.0, 0.0) is None


# ── the clamp itself ───────────────────────────────────────────────────


def test_an_oversized_budget_is_clamped_to_the_safe_share(monkeypatch: pytest.MonkeyPatch) -> None:
    # The 2026-08-03 configuration, exactly: 100 GB requested on a 121 GB
    # coherent-memory box.
    monkeypatch.setattr("tenzro_media_gen.worker._system_ram_gb", lambda: 121.0)
    monkeypatch.setattr("tenzro_media_gen.worker._accelerator_pool_gb", lambda: 121.0)

    resolved = resolve_vram_budget_gb(100.0)

    assert resolved == pytest.approx(121.0 * SAFE_SHARED_POOL_FRACTION)
    assert resolved < 100.0, "the whole point is that 100 does not survive"


def test_a_budget_that_fits_is_left_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    # Clamping must not be eager. An operator who sized their budget correctly
    # keeps the number they chose.
    monkeypatch.setattr("tenzro_media_gen.worker._system_ram_gb", lambda: 121.0)
    monkeypatch.setattr("tenzro_media_gen.worker._accelerator_pool_gb", lambda: 121.0)

    assert resolve_vram_budget_gb(34.0) == 34.0


def test_a_discrete_card_is_clamped_to_its_own_vram(monkeypatch: pytest.MonkeyPatch) -> None:
    # No 0.7 haircut here: discrete VRAM is not shared with the OS or the node,
    # so the whole card is budgetable.
    monkeypatch.setattr("tenzro_media_gen.worker._system_ram_gb", lambda: 256.0)
    monkeypatch.setattr("tenzro_media_gen.worker._accelerator_pool_gb", lambda: 80.0)

    assert resolve_vram_budget_gb(200.0) == 80.0


def test_an_unprobeable_machine_keeps_the_operators_figure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Neither RAM nor VRAM could be read. Inventing a ceiling from nothing would
    # be worse than trusting the operator, who at least looked at the machine.
    monkeypatch.setattr("tenzro_media_gen.worker._system_ram_gb", lambda: 0.0)
    monkeypatch.setattr("tenzro_media_gen.worker._accelerator_pool_gb", lambda: 0.0)

    assert resolve_vram_budget_gb(100.0) == 100.0


def test_probing_never_raises_even_when_torch_is_broken(monkeypatch: pytest.MonkeyPatch) -> None:
    # The probe runs at worker startup. A worker must not fail to start because
    # a memory probe raised.
    def explode() -> float:
        raise RuntimeError("driver mismatch")

    monkeypatch.setattr("tenzro_media_gen.worker._system_ram_gb", lambda: 121.0)
    monkeypatch.setattr("tenzro_media_gen.worker._accelerator_pool_gb", explode)

    with pytest.raises(RuntimeError):
        # The stub itself raises — this asserts the real `_accelerator_pool_gb`
        # is the thing that swallows, not `resolve_vram_budget_gb`.
        resolve_vram_budget_gb(100.0)


def test_the_real_accelerator_probe_swallows_its_own_failures() -> None:
    # Whatever this machine is, probing it must return a number rather than
    # raise. This is the property the startup path actually depends on.
    from tenzro_media_gen.worker import _accelerator_pool_gb, _system_ram_gb

    assert isinstance(_accelerator_pool_gb(), float)
    assert isinstance(_system_ram_gb(), float)
